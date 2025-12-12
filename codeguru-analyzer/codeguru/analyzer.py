import json
import os
import re
import shutil
import time
import zipfile
import tempfile
from collections import defaultdict
from pathlib import Path
import logging
import concurrent.futures
import boto3
import botocore
import requests
import math
from datetime import datetime, date # Import datetime and date

# Configure logging
# Adjust level and format as needed
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Helper function to get directory size (approximation)
def get_dir_size_mb(directory):
    """Calculates the size of a directory in MB."""
    total_size = 0
    try:
        for entry in os.scandir(directory):
            if entry.is_file():
                total_size += entry.stat().st_size
            elif entry.is_dir():
                total_size += get_dir_size_mb(entry.path) # Recursively sum subdirectories
    except Exception as e:
        logger.warning(f"Error calculating directory size for {directory}: {e}")
        return 0 # Return 0 on error to avoid stopping processing

    return total_size / (1024 * 1024) # Size in MB

# --- Custom JSON Encoder for handling datetime objects ---
class DateTimeEncoder(json.JSONEncoder):
    """
    Custom JSON encoder to handle datetime and date objects by converting them
    to ISO 8601 strings.
    """
    def default(self, obj):
        if isinstance(obj, (datetime, date)):
            return obj.isoformat()
        # Let the base class default method raise the TypeError for other types
        return json.JSONEncoder.default(self, obj)

# --- CodeGuruAnalyzer Class (rest of the class remains largely the same) ---

class CodeGuruAnalyzer:
    """
    Analyzes code snippets using AWS CodeGuru Security via boto3,
    supporting batch processing with size constraints.
    """
    DEFAULT_REGION = "us-east-1"
    MAX_POLL_ATTEMPTS = 20 # Increased polling attempts
    POLL_SLEEP_SECONDS = 15 # Increased sleep time
    DEFAULT_SEVERITIES_TO_IGNORE = {"Low", "Info"}
    DEFAULT_CODE_SUBDIR = "code_src"  # Standard subdirectory within the zip

    # CodeGuru Security limit on uncompressed code artifact size
    MAX_BATCH_UNCOMPRESSED_SIZE_MB = 50

    def __init__(self,
                 region=None,
                 severities_to_ignore={"Low", "Info"},
                 code_subdir=DEFAULT_CODE_SUBDIR,
                 include_raw=False):

        self.region = region or self.DEFAULT_REGION
        self.client = None
        self.severities_to_ignore = severities_to_ignore if severities_to_ignore is not None else self.DEFAULT_SEVERITIES_TO_IGNORE
        self.code_subdir = code_subdir
        self.include_raw = include_raw

        try:
            logger.info(f"Initializing CodeGuru Security client in region: {self.region}")
            self.client = boto3.client('codeguru-security', region_name=self.region)
            # Test connectivity (optional, but recommended)
            # This requires at least list permissions
            try:
                 self.client.list_scans(maxResults=1)
                 logger.info("CodeGuru Security client initialized and connected successfully.")
            except botocore.exceptions.ClientError as e:
                 logger.error(f"CodeGuru API call failed during initialization check: {e}")
                 logger.warning("Client initialized but connectivity check failed. Ensure permissions are correct.")
                 raise
            except Exception as e:
                 logger.warning(f"Unexpected error during client connectivity check: {e}", exc_info=True)
                 raise


        except botocore.exceptions.NoCredentialsError:
            logger.error("AWS credentials not found. Ensure credentials are configured (environment variables, ~/.aws/credentials, IAM role).")
            raise # Re-raise to signal failure to the caller
        except Exception as e:
            logger.error(f"Failed to initialize CodeGuru Security client: {e}", exc_info=True)
            raise # Re-raise

        logger.info(f"CodeGuruAnalyzer initialized with region: {self.region}")
        logger.info(f"Ignoring severities: {self.severities_to_ignore}")
        logger.info(f"Using code subdirectory in zip: '{self.code_subdir}'")


    def _create_code_zip(self, code_data_batch, base_temp_dir, file_extension=".py"):
        """
        Creates a zip archive containing the code data for a single batch.
        Includes a check against the uncompressed size limit.
        (Internal Method)

        Args:
            code_data_batch (list): List of dicts, each with 'id' and 'code'.
            base_temp_dir (Path): The base temporary directory path.
            file_extension (str): The file extension for code files.

        Returns:
            Path: The path to the created zip file, or None on failure/empty batch.

        Raises:
            ValueError: If the uncompressed size of the batch exceeds the limit.
        """
        if not code_data_batch:
            logger.warning("No code data provided for this batch.")
            return None

        input_dir = base_temp_dir / "codeguru_input_batch"
        input_code_dir = input_dir / self.code_subdir  # Place code in the configured subdir
        input_code_dir.mkdir(parents=True, exist_ok=True)

        zip_file_path = base_temp_dir / "codeguru_input_batch.zip"

        logger.info(f"Preparing input code in temporary directory: {input_code_dir}")

        files_to_zip = []
        current_batch_uncompressed_size = 0 # Use bytes for precision

        for sample in code_data_batch:
            record_id = sample.get('id')
            code = sample.get('code')

            if record_id is None or code is None:
                logger.error(f"Error: found sample with missing 'id' or 'code': {sample}")
                return None # Fail the entire zip creation if any item is malformed

            # Use a sanitized filename just in case 'id' has problematic characters
            sanitized_id = re.sub(r'[^\w.-]', '_', str(record_id))
            code_file_name = f"{sanitized_id}{file_extension}"
            code_file_path = input_code_dir / code_file_name

            try:
                code_bytes = code.encode('utf-8')
                file_size_bytes = len(code_bytes)

                # Check size limit *before* writing the file
                if (current_batch_uncompressed_size + file_size_bytes) > self.MAX_BATCH_UNCOMPRESSED_SIZE_MB * 1024 * 1024:
                     # This item pushes the batch over the limit.
                     logger.error(f"Item '{record_id}' ({file_size_bytes / (1024*1024):.2f}MB) exceeds CodeGuru Security's uncompressed size limit ({self.MAX_BATCH_UNCOMPRESSED_SIZE_MB}MB) when added to the current batch ({current_batch_uncompressed_size / (1024*1024):.2f}MB). This batch will be incomplete.")
                     return None # Strict mode: Fail the entire zip creation if an item is too large

                with open(code_file_path, 'wb') as code_file: # Write bytes
                     code_file.write(code_bytes)

                files_to_zip.append(code_file_path)
                current_batch_uncompressed_size += file_size_bytes


            except IOError as e:
                logger.error(f"Failed to write code file {code_file_path}: {e}")
                # Strict mode: Fail the entire zip creation if a file write fails
                return None
            except Exception as e:
                 logger.error(f"An unexpected error occurred processing code for {record_id}: {e}", exc_info=True)
                 # Strict mode: Fail the entire zip creation on unexpected error
                 return None

        if not files_to_zip:
            logger.warning("No valid code files to zip in this batch after processing.")
            # Strict mode: An empty zip is a problem if batch_data was not empty
            # If batch_data was empty, _create_code_zip returned None early.
            # If batch_data was not empty but files_to_zip is, something went wrong processing all items.
            if code_data_batch:
                 logger.error("Batch data was provided but no valid files were created to zip.")
                 return None # Strict mode: Fail zip creation if no files were successfully processed

            return None # Original behavior: return None if no files to zip


        logger.info(f"Zipping input directory '{input_dir}' to '{zip_file_path}' ({current_batch_uncompressed_size / (1024*1024):.2f}MB uncompressed size).")
        try:
            with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in files_to_zip:
                    # arcname should be relative to input_dir (e.g., code_src/file1.py)
                    archive_name = file_path.relative_to(input_dir)
                    zipf.write(file_path, arcname=archive_name)

            # shutil.rmtree(input_dir)  # Clean up the source dir after zipping - handle this in the calling method's tempdir context
            logger.info(f"Input zip created: {zip_file_path}")
            return zip_file_path
        except Exception as e:
            logger.error(f"Failed to create zip file: {e}", exc_info=True)
            return None # Strict mode: Fail zip creation on zipping error


    def _upload_to_s3(self, zip_file_path, scan_name):
        """
        Gets a pre-signed URL from CodeGuru and uploads the zip file using requests.
        (Internal Method - Adapted from Code 2)

        Args:
            zip_file_path (Path): Path to the zip file to upload.
            scan_name (str): The unique name for the scan.

        Returns:
            dict: Response from create_upload_url containing S3 details and
                  codeArtifactId, or None on failure.
        """
        if not zip_file_path or not zip_file_path.exists():
             logger.error(f"Zip file not found for upload: {zip_file_path}")
             return None

        try:
            logger.info(f"Requesting upload URL for scan: {scan_name}")
            upload_url_response = self.client.create_upload_url(scanName=scan_name)
            s3_url = upload_url_response.get('s3Url')
            code_artifact_id = upload_url_response.get('codeArtifactId')

            if not s3_url or not code_artifact_id:
                 logger.error(f"create_upload_url response is missing s3Url or codeArtifactId. Response: {upload_url_response}")
                 return None

            logger.info(f"Uploading {zip_file_path.name} to pre-signed S3 URL...")
            headers = upload_url_response.get('requestHeaders', {})
            # Ensure Content-Type is set, although S3 might infer it
            if 'Content-Type' not in headers:
                 headers['Content-Type'] = 'application/zip'
            # Add Content-Length header
            headers['Content-Length'] = str(zip_file_path.stat().st_size)


            with open(zip_file_path, 'rb') as f:
                upload_response = requests.put(s3_url, data=f, headers=headers)
                upload_response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            logger.info(f"Upload successful (HTTP Status: {upload_response.status_code}).")
            # Return the response object itself, or just the key pieces needed later
            # The codeArtifactId is crucial for starting the scan
            return {'codeArtifactId': code_artifact_id} # Simplified return


        except botocore.exceptions.ClientError as e:
            logger.error(f"AWS API error during upload URL creation or upload: {e}", exc_info=True)
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to upload code artifact to S3 using requests: {e}", exc_info=True)
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"S3 Upload Response Status Code: {e.response.status_code}")
                # logger.error(f"S3 Upload Response Text: {e.response.text}") # Be cautious about logging response body
            return None
        except IOError as e:
             logger.error(f"Failed to read zip file {zip_file_path}: {e}", exc_info=True)
             return None
        except Exception as e:
             logger.error(f"An unexpected error occurred during S3 upload process: {e}", exc_info=True)
             return None


    def _start_and_poll_scan(self, code_artifact_id, scan_name, batch_num=None):
        """
        Starts the CodeGuru scan and polls for its completion status.
        (Internal Method - Adapted from Code 2)

        Args:
            code_artifact_id (str): The ID of the uploaded code artifact.
            scan_name (str): The unique name for the scan.
            batch_num (int, optional): The batch number for logging context.

        Returns:
            tuple: (scan_status, run_id, scan_name). Status is 'Succeeded',
                   'Failed', 'Timeout', etc. run_id is None on setup failure.
        """
        run_id = None
        batch_context = f"[Batch {batch_num}] " if batch_num is not None else ""
        try:
            resource_id = {'codeArtifactId': code_artifact_id}

            logger.info(f"{batch_context}Starting CodeGuru Security scan '{scan_name}' for resource: {resource_id}")
            create_scan_response = self.client.create_scan(
                resourceId=resource_id,
                scanName=scan_name,
                scanType='Standard',
                analysisType='Security'
            )
            run_id = create_scan_response.get('runId')
            if not run_id:
                 logger.error(f"{batch_context}create_scan response did not contain 'runId'. Response: {create_scan_response}")
                 return 'Failed', None, scan_name # Indicate failure

            logger.info(f"{batch_context}Scan initiated successfully. Run ID: {run_id}")

            logger.info(f"{batch_context}Polling scan status for Run ID: {run_id} (Scan Name: {scan_name})...")
            for attempt in range(self.MAX_POLL_ATTEMPTS):
                logger.debug(f"{batch_context}Polling attempt {attempt + 1}/{self.MAX_POLL_ATTEMPTS}...")
                try:
                    scan_status_response = self.client.get_scan(
                        runId=run_id,
                        scanName=scan_name
                    )
                    scan_state = scan_status_response.get('scanState')
                    if not scan_state:
                        logger.error(f"{batch_context}get_scan response did not contain 'scanState'. Response: {scan_status_response}")
                        return 'Failed', run_id, scan_name

                    logger.info(f"{batch_context}Current scan state: {scan_state}")

                    # Use a more robust check for success state
                    success_states = ['Succeeded', 'Successful'] # Add 'Successful' if API might return it
                    if scan_state in success_states:
                        logger.info(f"{batch_context}Scan completed successfully.")
                        return 'Succeeded', run_id, scan_name
                    elif scan_state == 'Failed':
                        logger.error(f"{batch_context}Scan failed. Reason: {scan_status_response.get('errorMessage', 'Unknown')}")
                        return 'Failed', run_id, scan_name
                    elif scan_state in ['Pending', 'InProgress']:
                        time.sleep(self.POLL_SLEEP_SECONDS)
                    else:
                         logger.warning(f"{batch_context}Encountered unexpected scan state: {scan_state}. Waiting...")
                         time.sleep(self.POLL_SLEEP_SECONDS)

                except botocore.exceptions.ResourceNotFoundException:
                    logger.warning(f"{batch_context}Scan {scan_name} with run ID {run_id} not found while polling. It might have been cleaned up or never started properly.")
                    return 'NotFound', run_id, scan_name
                except botocore.exceptions.ClientError as e:
                    logger.error(f"{batch_context}AWS API error while polling scan {scan_name}: {e}", exc_info=True)
                    return 'ClientError', run_id, scan_name
                except Exception as e:
                     logger.error(f"{batch_context}An unexpected error occurred during polling for scan {scan_name}: {e}", exc_info=True)
                     return 'Error', run_id, scan_name


            logger.warning(f"{batch_context}Scan polling timed out for scan {scan_name} (run {run_id}) after {self.MAX_POLL_ATTEMPTS * self.POLL_SLEEP_SECONDS} seconds.")
            return 'Timeout', run_id, scan_name

        except botocore.exceptions.ClientError as e:
            operation_name = e.operation_name if hasattr(e, 'operation_name') else 'Unknown'
            logger.error(f"{batch_context}AWS API error during operation '{operation_name}' for scan {scan_name}: {e}", exc_info=True)
            status = 'Failed' if run_id else 'Setup Failed' # Distinguish setup vs polling failure
            return status, run_id, scan_name # Indicate setup failure
        except Exception as e:
            logger.error(f"{batch_context}An unexpected error occurred during scan initiation or polling setup for scan {scan_name}: {e}", exc_info=True)
            status = 'Failed' if run_id else 'Setup Failed' # Distinguish setup vs polling failure
            return status, run_id, scan_name # Indicate setup failure


    def _get_findings(self, scan_name, batch_num=None):
        """
        Retrieves all findings for a given scan name using pagination.
        (Internal Method - Adapted from Code 2)

        Args:
            scan_name (str): The Scan Name of the completed CodeGuru scan.
            batch_num (int, optional): The batch number for logging context.

        Returns:
            list: A list of finding dictionaries, or None on failure. An empty
                  list is returned if there are no findings but the API call succeeded.
        """
        all_findings = []
        batch_context = f"[Batch {batch_num}] " if batch_num is not None else ""
        try:
            logger.info(f"{batch_context}Retrieving findings for Scan Name: {scan_name}")
            paginator = self.client.get_paginator('get_findings')
            page_iterator = paginator.paginate(scanName=scan_name)

            finding_count = 0
            for page in page_iterator:
                findings = page.get('findings', [])
                finding_count += len(findings)
                all_findings.extend(findings)

            logger.info(f"{batch_context}Retrieved {finding_count} total findings for scan {scan_name}.")
            # Return the potentially empty list if no findings, but retrieval succeeded
            return all_findings

        except botocore.exceptions.ResourceNotFoundException:
            logger.warning(f"{batch_context}Scan {scan_name} not found when trying to retrieve findings. It might have been cleaned up or failed early.")
            return None # Strict mode: Resource not found during findings retrieval is a failure
        except botocore.exceptions.ClientError as e:
            logger.error(f"{batch_context}AWS API error retrieving findings for scan {scan_name}: {e}", exc_info=True)
            return None # Strict mode: AWS API error during findings retrieval is a failure
        except Exception as e:
             logger.error(f"{batch_context}An unexpected error occurred while retrieving findings for scan {scan_name}: {e}", exc_info=True)
             return None # Strict mode: Any unexpected error during findings retrieval is a failure


    def _parse_findings(self, raw_findings, include_raw=False):
        """
        Parses raw CodeGuru findings into a structured dictionary,
        filtering by severity. Optionally includes the full raw finding.
        (Internal Method - Adapted from Code 1)

        Args:
            raw_findings (list): A list of raw finding dictionaries from CodeGuru.
            include_raw (bool): If True, includes the full raw finding dictionary
                                under the key 'raw_finding'.

        Returns:
            dict: A dictionary where keys are original record_ids and values are
                  lists of parsed finding dictionaries, or None on failure.
        """
        if raw_findings is None: # Handle the case where _get_findings returned None
            logger.error("Cannot parse findings: raw findings input is None.")
            return None # Strict mode: Cannot proceed if raw findings retrieval failed

        if not raw_findings:
            logger.info("No raw findings to parse.")
            return {} # Return empty dict if there are no findings (successful retrieval)

        logger.info(f"Parsing {len(raw_findings)} raw findings.")
        parsed_findings = defaultdict(list) # Use defaultdict for easy appending

        for finding in raw_findings:
            try:
                severity = finding.get("severity")
                if severity in self.severities_to_ignore:
                    logger.debug(f"Ignoring finding with severity: {severity}")
                    continue  # Skip ignored severities

                # Robustly access nested data
                vulnerability = finding.get('vulnerability', {})
                file_path_info = vulnerability.get('filePath', {})
                remediation = finding.get('remediation', {})
                recommendation_info = remediation.get('recommendation', {})

                # Extract original file name (without extension and potential suffix)
                # Code 1's logic for this seems correct assuming the filename format
                file_name = file_path_info.get('name', '')
                # Remove the .py extension and potentially the '_<suffix>' if present, though the zipping uses just sanitized_id
                # Let's assume the filename is just the sanitized_id.py for now.
                record_id = Path(file_name).stem # Gets filename without extension

                if not record_id:
                    logger.error(f"Skipping finding due to missing or empty file name: {file_name}. Raw finding: {finding}")
                    # Strict mode: Fail parsing if a finding has no discernible record_id
                    return None
                    # continue # Original behavior: Skip the finding


                description = finding.get('description', 'N/A')
                title = finding.get('title', 'N/A')
                recommendation = recommendation_info.get('text', 'N/A')

                code_snippet_lines = file_path_info.get('codeSnippet', [])
                vulnerability_start = file_path_info.get('startLine')
                vulnerability_end = file_path_info.get('endLine')

                code_snippet = ""
                vulnerable_part = ""

                # Ensure start/end lines are integers if present
                try:
                    start_line = int(vulnerability_start) if vulnerability_start is not None else -1
                    end_line = int(vulnerability_end) if vulnerability_end is not None else -1
                    # Adjust end_line to be inclusive if start_line is valid
                    if start_line != -1 and end_line != -1:
                         end_line = max(start_line, end_line) # Ensure end is not less than start
                except (ValueError, TypeError):
                    logger.error(
                        f"Invalid start/end line numbers for finding in {record_id}: {vulnerability_start}/{vulnerability_end}. Skipping vulnerable part highlighting.")
                    # Strict mode: Fail parsing if line numbers are invalid for a finding
                    return None
                    # start_line, end_line = -1, -1  # Disable highlighting - Original behavior

                snippet_lines_map = {}
                full_snippet_content = [] # Use a list to reconstruct the full snippet accurately
                for line_info in code_snippet_lines:
                     content = line_info.get('content', '')
                     line_num = line_info.get('number')
                     full_snippet_content.append(content) # Add line content to the list

                     try:
                          line_num_int = int(line_num) if line_num is not None else -1
                          if line_num_int != -1:
                               snippet_lines_map[line_num_int] = content
                     except (ValueError, TypeError):
                          logger.error(f"Invalid line number '{line_num}' in code snippet for {record_id}.")
                          # Strict mode: Fail parsing if snippet line numbers are invalid
                          return None
                          # continue # Original behavior: Skip this line info

                code_snippet = "\n".join(full_snippet_content) # Join lines to get the full snippet


                # Reconstruct vulnerable part based on parsed line numbers and snippet map
                if start_line != -1 and end_line != -1:
                     vulnerable_lines = []
                     for line_num in range(start_line, end_line + 1):
                          if line_num in snippet_lines_map:
                               vulnerable_lines.append(snippet_lines_map[line_num])
                          else:
                               logger.warning(f"Line number {line_num} within vulnerable range [{start_line}-{end_line}] not found in snippet map for {record_id}.")
                               # Strict mode: Fail parsing if a vulnerable line is missing from the snippet map
                               # return None
                               # vulnerable_lines.append(f"[Line {line_num} content not available]") # Placeholder - Original behavior

                     vulnerable_part = "\n".join(vulnerable_lines)
                else:
                     vulnerable_part = "Vulnerable part highlighting not available."


                # Create the parsed finding dictionary
                parsed_finding_dict = {
                    "title": title,
                    "severity": severity,
                    "description": description,
                    "recommendation": recommendation,
                    "code_snippet": code_snippet.strip(),
                    "vulnerable_part": vulnerable_part.strip(),
                }

                # Optionally include the full raw finding
                if include_raw:
                     # Ensure the raw finding is also JSON serializable if needed,
                     # though the DateTimeEncoder should handle top-level datetimes.
                     # Deeply nested datetimes *might* still cause issues,
                     # but the custom encoder applied during dump should catch them.
                    parsed_finding_dict["raw_finding"] = finding


                # Add finding to the list for this record_id
                parsed_findings[record_id].append(parsed_finding_dict)

            except Exception as e:
                # Catch unexpected errors during parsing a single finding
                finding_id = finding.get('id', 'N/A')
                logger.error(f"Error parsing individual finding ID {finding_id}: {e}", exc_info=True)
                # Strict mode: Fail the entire parsing if an individual finding parse fails
                return None
                # continue  # Skip this finding - Original behavior


        logger.info(f"Parsing complete. Found relevant findings for {len(parsed_findings)} records.")
        return parsed_findings # Return the results if parsing was successful for all included findings


    def _analyze_single_batch(self, batch_data, batch_num, total_batches, temp_base_dir):
         """
         Analyzes a single batch of code data using CodeGuru Security via boto3.
         (Internal Helper Method)

         Args:
             batch_data (list): List of dicts for this batch.
             batch_num (int): The index of the current batch (0-based).
             total_batches (int): The total number of batches.
             temp_base_dir (Path): The base temporary directory for this run.

         Returns:
             tuple: (batch_num, scan_status, parsed_findings, error_message)
                    scan_status is 'Succeeded' or indicates failure ('Failed',
                    'Timeout', 'NotFound', 'ClientError', 'Error', 'Setup Failed').
                    parsed_findings is a dict or None on failure.
                    error_message is a string or None.
         """
         batch_context = f"[Batch {batch_num + 1}/{total_batches}]"
         # Ensure scan_name is unique across concurrent runs and batches
         # Adding PID provides uniqueness if multiple scripts run simultaneously
         scan_name = f"codeguru-batch-scan-{int(time.time())}-{os.getpid()}-{batch_num}"

         logger.info(f"{batch_context} Starting analysis for batch with {len(batch_data)} items.")

         # Use a dedicated temp directory for this batch
         # This ensures cleanup even if a batch fails unexpectedly mid-process
         with tempfile.TemporaryDirectory(prefix=f"codeguru_batch_{scan_name}_", dir=temp_base_dir) as batch_temp_dir_str:
             batch_temp_dir = Path(batch_temp_dir_str)
             logger.info(f"{batch_context} Using temporary directory: {batch_temp_dir}")

             try:
                 # 1. Create input zip for the batch
                 zip_file_path = self._create_code_zip(batch_data, batch_temp_dir)
                 if not zip_file_path:
                     logger.error(f"{batch_context} Failed to create code archive. Aborting batch.")
                     return batch_num, 'Failed', None, "Failed to create code archive." # Return None for findings on failure

                 # 2. Upload to S3
                 upload_response = self._upload_to_s3(zip_file_path, scan_name)
                 if not upload_response or 'codeArtifactId' not in upload_response:
                      logger.error(f"{batch_context} Failed to upload code artifact. Aborting batch.")
                      return batch_num, 'Failed', None, "Failed to upload code artifact to S3." # Return None for findings on failure

                 code_artifact_id = upload_response['codeArtifactId']

                 # 3. Start and Poll Scan
                 scan_status, run_id, _ = self._start_and_poll_scan(code_artifact_id, scan_name, batch_num=batch_num)

                 # In strict mode, any status other than 'Succeeded' indicates a failure for this batch.
                 if scan_status not in ['Succeeded']:
                     logger.error(f"{batch_context} Scan did not succeed. Status: {scan_status}. Aborting batch.")
                     error_message = f"CodeGuru scan failed with status: {scan_status}"
                     if scan_status == 'Timeout':
                          error_message = "CodeGuru scan timed out."
                     elif scan_status == 'NotFound':
                          error_message = "CodeGuru scan artifact or scan not found after starting."
                     elif scan_status == 'ClientError':
                          error_message = "AWS API error occurred during scan polling."
                     elif scan_status == 'Error':
                          error_message = "An unexpected error occurred during scan polling."
                     elif scan_status == 'Setup Failed':
                           error_message = "CodeGuru scan failed to initiate."
                     else:
                          # Attempt to get scan details even if failed, might have error message
                          try:
                              if run_id: # Only try to get details if a run_id was obtained
                                  scan_details = self.client.get_scan(runId=run_id, scanName=scan_name)
                                  if 'errorMessage' in scan_details:
                                      error_message += f" AWS Error: {scan_details['errorMessage']}"
                          except Exception:
                              pass # Ignore errors getting scan details

                     # Note: The original code attempted to get findings even on failure,
                     # but in strict mode, if the scan itself failed, there are no valid findings.
                     return batch_num, scan_status, None, error_message # Return None for findings on failure

                 # 4. Get Findings
                 raw_findings = self._get_findings(scan_name, batch_num=batch_num)
                 # _get_findings now returns None on failure, [] on no findings.
                 if raw_findings is None:
                      logger.error(f"{batch_context} Failed to retrieve findings. Aborting batch.")
                      return batch_num, 'Failed', None, "Failed to retrieve findings." # Return None for findings on failure

                 # 5. Parse Findings
                 # Pass include_raw=True if you want the full raw finding in the output
                 parsed_findings = self._parse_findings(raw_findings, include_raw=self.include_raw)
                 # _parse_findings now returns None on failure.
                 if parsed_findings is None:
                      logger.error(f"{batch_context} Failed to parse findings. Aborting batch.")
                      return batch_num, 'Failed', None, "Failed to parse findings." # Return None for findings on failure


                 logger.info(f"{batch_context} Batch analysis completed successfully. Found {len(parsed_findings)} records with findings.")

                 # The temporary directory for the batch is cleaned up automatically here
                 # Even on failure, the 'with' block handles the temp dir cleanup for this batch.
                 return batch_num, 'Succeeded', parsed_findings, None

             except Exception as e:
                 logger.error(f"{batch_context} An unexpected error occurred during batch analysis: {e}", exc_info=True)
                 # Strict mode: Any unexpected exception means the batch failed entirely.
                 return batch_num, 'Failed', None, f"An unexpected error occurred during batch processing: {e}"

    def analyze_code(self,
                     code_data,
                     max_batch_items=1000,  # Max items per batch (soft limit)
                     max_batch_uncompressed_size_mb=MAX_BATCH_UNCOMPRESSED_SIZE_MB,  # Hard limit for CodeGuru
                     max_workers=8,  # Number of concurrent batches
                     output_path_prefix="codeguru_batch_output_",
                     merge_output_path="merged_codeguru_output.json",
                     delete_partials=True,
                     sleep_time_between_batches=5): # Delay between submitting batch tasks
        
        if not code_data:
            logger.warning("No code data provided for batch analysis.")
            if merge_output_path:
                # Create an empty merged output file if requested but no data
                try:
                    with open(merge_output_path, 'w') as outfile:
                        # Use the custom encoder for the empty dict just in case
                        json.dump({}, outfile, indent=4, cls=DateTimeEncoder)
                    logger.info(f"No code data, created empty merged output file: {merge_output_path}")
                except IOError as e:
                    logger.error(f"Failed to create empty merged output file {merge_output_path}: {e}")
                except TypeError as e:
                    logger.error(f"Failed to serialize empty dict with DateTimeEncoder for {merge_output_path}: {e}")

            return {}  # Return empty dict if no data

        if self.client is None:
            logger.error("CodeGuru client not initialized. Cannot perform analysis.")
            return None  # --- MODIFIED: Return None on client initialization failure ---

        # --- Batching Logic with Size Consideration ---
        batches = []
        current_batch_data = []
        current_batch_uncompressed_size = 0  # Use bytes for precision
        batch_counter = 0

        logger.info(
            f"Starting batching process with max items per batch: {max_batch_items}, max uncompressed size: {max_batch_uncompressed_size_mb}MB.")

        # Calculate total size beforehand for a more accurate initial split estimate (optional but helpful)
        # total_data_size_mb = sum(len(item.get('code', '').encode('utf-8')) for item in code_data if item.get('code')) / (1024*1024)
        # logger.info(f"Total estimated uncompressed data size: {total_data_size_mb:.2f}MB")

        for item in code_data:
            record_id = item.get('id')
            code = item.get('code')
            if record_id is None or not isinstance(code, str):  # Ensure code is a string
                logger.error(
                    f"Invalid item during batching due to missing 'id' or invalid 'code' type: {item}")
                return None

            # Estimate uncompressed size for the current item
            try:
                # Ensure encoding only happens if 'code' is a non-empty string
                item_size_bytes = len(code.encode('utf-8')) if code else 0
            except Exception as e:
                logger.warning(f"Could not estimate size for item {record_id}: {e}. Assuming 0 bytes.")
                # --- MODIFIED: Treat encoding error during batching as a failure? ---
                # Original assumed 0 bytes. Strictness implies this is a failure.
                # For minimal change, let's keep assuming 0 here, but note it as a potential point.
                item_size_bytes = 0

            # Check if adding this item exceeds size or item count limits
            # Note: item_size_bytes / (1024 * 1024) gives size in MB
            if ((current_batch_uncompressed_size + item_size_bytes) > max_batch_uncompressed_size_mb * 1024 * 1024 or
                len(current_batch_data) >= max_batch_items):
                # Start a new batch if the current one is not empty
                if current_batch_data:
                     logger.info(f"Batch {batch_counter} finalized with {len(current_batch_data)} items and {current_batch_uncompressed_size / (1024*1024):.2f}MB.")
                     batches.append(current_batch_data)
                     batch_counter += 1
                     current_batch_data = [] # Reset for new batch
                     current_batch_uncompressed_size = 0

                # Check if the single item itself exceeds the size limit (hard limit)
                if item_size_bytes > max_batch_uncompressed_size_mb * 1024 * 1024:
                     logger.error(f"Item '{record_id}' ({item_size_bytes / (1024*1024):.2f}MB) exceeds the single item/batch uncompressed size limit ({max_batch_uncompressed_size_mb}MB). It cannot be processed.")
                     # Skip this item entirely as it cannot fit in any batch
                     continue

            # Add the item to the current batch
            current_batch_data.append(item)
            current_batch_uncompressed_size += item_size_bytes

        # Add the last batch if not empty
        if current_batch_data:
            logger.info(
                f"Batch {batch_counter} finalized with {len(current_batch_data)} items and {current_batch_uncompressed_size / (1024 * 1024):.2f}MB estimated.")
            batches.append(current_batch_data)
            batch_counter += 1

        logger.info(f"Batching complete. Created {len(batches)} batches.")

        # --- MODIFIED: Check if any batches were created ---
        # If code_data was not empty but no valid batches were created (e.g., all items invalid/too large)
        if not batches and code_data:
            logger.error(
                "Input data provided but no valid batches were created. Check batching logic or input data format. Aborting analysis.")
            return None  # Strict mode: Fail if data exists but no batches formed

        # --- Process Batches with Concurrent Execution ---
        # Use a single base temporary directory for the entire run
        with tempfile.TemporaryDirectory(prefix="codeguru_run_") as temp_base_dir_str:
            temp_base_dir = Path(temp_base_dir_str)
            logger.info(f"Using base temporary directory for run: {temp_base_dir}")

            batch_results = []  # Store results from successful batches (parsed findings dicts)
            partial_output_files = []  # Store paths of saved partial files

            # Use ThreadPoolExecutor for concurrent I/O and polling waits
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_batch = {
                    executor.submit(
                        self._analyze_single_batch,
                        batch_data=batches[i],
                        batch_num=i,
                        total_batches=len(batches),
                        temp_base_dir=temp_base_dir  # Pass the base temp dir
                    ): i for i in range(len(batches))
                }

                # Process results as they complete
                for future in concurrent.futures.as_completed(future_to_batch):
                    batch_index = future_to_batch[future]
                    batch_context = f"[Batch {batch_index + 1}/{len(batches)}]"
                    try:
                        # Result is (batch_num, scan_status, parsed_findings, error_message)
                        _, scan_status, parsed_findings, error_message = future.result()

                        if scan_status != 'Succeeded' or parsed_findings is None:
                            logger.error(
                                f"{batch_context} Batch analysis failed or returned no findings due to a critical error. Status: {scan_status}. Error: {error_message or 'None'}. Aborting entire analysis.")
                            return None  # Strict mode: Return None on any batch failure

                        logger.info(
                            f"{batch_context} Analysis finished successfully with status: {scan_status}.")  # Log success

                        # If successful, append results and save partials
                        # parsed_findings is a dict (potentially empty) if scan_status was 'Succeeded'
                        batch_results.append(parsed_findings)  # Still collect results from successful batches

                        # Optionally save partial results immediately
                        if output_path_prefix:
                            # Ensure partial output path is robust
                            partial_path = Path(
                                f"{output_path_prefix}{batch_index:04d}.json")  # Add zero padding for sorting
                            try:
                                partial_path.parent.mkdir(parents=True, exist_ok=True)
                                with open(partial_path, 'w', encoding='utf-8') as f:
                                    # Use the custom encoder when dumping partial results
                                    json.dump(parsed_findings, f, indent=4, cls=DateTimeEncoder)
                                partial_output_files.append(partial_path)
                                logger.info(f"{batch_context} Partial results saved to {partial_path}")
                            except IOError as e:
                                logger.error(f"{batch_context} Failed to save partial findings to {partial_path}: {e}")
                                return None


                    except Exception as exc:
                        # This catches unexpected errors during future.result() itself (worker crashed)
                        logger.error(f"{batch_context} An unhandled exception occurred during batch execution: {exc}",
                                     exc_info=True)
                        return None  # Strict mode: Return None on any batch execution exception


                    time.sleep(sleep_time_between_batches)

            logger.info("All batch tasks completed.")

        # --- Merge and Cleanup ---
        final_merged_data = {}

        # Merge all batch results into final_merged_data
        # This only happens if all batches completed without triggering an early return None
        for batch_findings_dict in batch_results:
            # --- Minimal Change: Ensure batch_findings_dict is a dict before updating ---
            # It should be if scan_status was 'Succeeded' and parsed_findings wasn't None,
            # but add a check just in case.
            if isinstance(batch_findings_dict, dict):
                final_merged_data.update(batch_findings_dict)
            else:
                logger.error(
                    f"Unexpected non-dict item in batch_results: {batch_findings_dict}. Skipping merge for this item.")

        # Only write to file if merge_output_path is provided
        if merge_output_path:
            logger.info(f"Merging results from {len(batch_results)} successful batches to {merge_output_path}...")
            try:
                merge_output_path_obj = Path(merge_output_path)
                merge_output_path_obj.parent.mkdir(parents=True, exist_ok=True)
                with open(merge_output_path_obj, 'w', encoding='utf-8') as outfile:
                    json.dump(final_merged_data, outfile, indent=4, cls=DateTimeEncoder)
                logger.info(f"Merged findings saved to: {merge_output_path}")
            except IOError as e:
                logger.error(f"Failed to save merged findings to {merge_output_path}: {e}")
            except TypeError as e:
                logger.error(f"Failed to serialize merged findings to JSON for {merge_output_path}: {e}. Error: {e}", exc_info=True)
            
            # Delete partial files if requested
            if delete_partials:
                logger.info("Deleting partial output files...")
                for file_path in partial_output_files:
                    try:
                        if file_path.exists():
                            os.remove(file_path)
                            logger.info(f"Deleted partial file: {file_path}")
                        else:
                             logger.warning(f"Partial file not found for deletion: {file_path}")
                    except Exception as e:
                        logger.error(f"Error deleting partial file {file_path}: {e}")
            else:
                logger.info("Skipping deletion of partial output files.")

        # The base temporary directory for the run is cleaned up automatically here
        logger.info("Base temporary directory and batch temporary directories cleaned up.")

        # Always return the merged dictionary IF the loop completed without returning None
        return final_merged_data

    @staticmethod
    def analyse_results(res_dict):
        """
        Analyzes a dictionary of vulnerability scan results to count unique
        vulnerabilities per file/context.

        Args:
          res_dict: A dictionary where keys are file names or contexts (strings)
                     and values are lists of vulnerability finding dictionaries.
                     Each finding dictionary must have a "title" key containing the
                     vulnerability name.

        Returns:
          A dictionary where keys are the unique vulnerability titles (strings)
          found across all files, and values are the counts of how many files
          contained that vulnerability at least once.
        """
        vulnerability_counts = defaultdict(int)  # Use defaultdict for easier counting

        # Iterate through each file/context and its list of findings
        for file_key, findings_list in res_dict.items():
            # Keep track of unique vulnerability titles found *within this specific file*
            # to ensure we only count each vulnerability once per file.
            seen_vulnerabilities_in_file = set()

            # Iterate through each finding reported for this file
            for finding in findings_list:
                # Safely get the title, handle cases where 'title' might be missing
                title = finding.get("title")

                # Check if a title exists and if we haven't already counted it for this file
                if title and title not in seen_vulnerabilities_in_file:
                    # Add the title to the set for this file
                    seen_vulnerabilities_in_file.add(title)
                    # Increment the overall count for this vulnerability title
                    vulnerability_counts[title] += 1

        # Sort the results by count (value) in descending order
        # 1. Get items as a list of (key, value) tuples: [('title1', count1), ('title2', count2)]
        sorted_items = list(vulnerability_counts.items())

        # 2. Sort the list using the second element (index 1, which is the count) as the key
        #    `reverse=True` ensures descending order (highest count first)
        sorted_items.sort(key=lambda item: item[1], reverse=True)

        # 3. Convert the sorted list of tuples back into a dictionary.
        #    In Python 3.7+, standard dictionaries remember insertion order,
        #    so this will preserve the sort order.
        sorted_vulnerability_counts = dict(sorted_items)

        return sorted_vulnerability_counts

# Example Usage (assuming you have 'code_data' as a list of {'id': '...', 'code': '...'}):
if __name__ == "__main__":
    def load_jsonl(file_path):
        data = []
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Skipping invalid JSON line: {line.strip()} - {e}")
        return data

    # Dummy code data for demonstration
    # dummy_code_data = [
    #     {'id': 'code_sample_1', 'code': 'import os\ndef insecure_function(file_name):\n    os.system("cat " + file_name)'},
    #     {'id': 'code_sample_2', 'code': 'def secure_function(data):\n    print(data)'},
    #     {'id': 'code_sample_3', 'code': 'import subprocess\ndef another_insecure_one(command):\n    subprocess.call(command, shell=True)'},
    #      {'id': 'code_sample_4', 'code': '# Just a comment\nprint("hello")'},
    #      # Add more samples to test batching
    #      *[
    #           {'id': f'filler_code_{i}', 'code': f'def dummy_func_{i}():\n    pass # This is filler code {i}'}
    #           for i in range(500) # Adjust count to test batch_size
    #      ],
    #      # Add a potentially large item to test size limit (adjust size as needed)
    #      # This item might exceed a batch if max_batch_uncompressed_size_mb is small
    #      # {'id': 'large_code_sample', 'code': 'x = """' + 'a' * (55 * 1024 * 1024) + '"""\ndef large_func(): pass'}, # 55MB - should cause issues
    #      {'id': 'medium_code_sample', 'code': 'x = """' + 'b' * (20 * 1024 * 1024) + '"""\ndef medium_func(): pass'}, # 20MB - should be okay in a batch
    #      {'id': 'another_insecure_one_2', 'code': 'import pickle\ndata = b"abc"\nobj = pickle.loads(data)'}, # Pickle vulnerability
    # ]

    INPUT_DATA_FILE = "step4-refinement-attempt-1-processed-output.jsonl"
    raw_data = load_jsonl(INPUT_DATA_FILE) # Uncomment and adjust if loading from file
    code_input_data = []
    for item in raw_data:
        record_id = item.get('id') or item.get('recordId') # Handle possible key names
        code = item.get('code')
        if record_id and isinstance(code, str):
            code_input_data.append({'id': record_id, 'code': code})
    dummy_code_data = code_input_data

    # Make sure you have AWS credentials configured (e.g., via environment variables or ~/.aws/credentials)
    # And permissions for codeguru-security:
    # - codeguru-security:CreateUploadUrl
    # - codeguru-security:CreateScan
    # - codeguru-security:GetScan
    # - codeguru-security:GetFindings
    # - s3:PutObject (on the pre-signed URL CodeGuru provides)


    analyzer = None
    try:
        # Initialize the analyzer
        analyzer = CodeGuruAnalyzer(
            region="us-east-1", # Replace with your desired region
            severities_to_ignore={"Low", "Info"}, # Ignore low and info findings
            include_raw=False # Set to True if you want to include the full raw finding in the output
        )
        print("CodeGuruAnalyzer initialized.")
    except Exception as e:
        print(f"Failed to initialize CodeGuruAnalyzer: {e}")
        print("Please ensure AWS credentials are configured and have necessary CodeGuru Security permissions.")
        exit()


    if analyzer:
        # Analyze the code data in batches
        print(f"\nAnalyzing {len(dummy_code_data)} code items in batches...")
        start_time = time.time()

        # Use a small batch size and fewer workers for demonstration
        results = analyzer.analyze_code(
            code_data=dummy_code_data,
            max_batch_items=5000, # Process up to 5000 items per batch
            max_batch_uncompressed_size_mb=analyzer.MAX_BATCH_UNCOMPRESSED_SIZE_MB, # Use the CodeGuru limit
            max_workers=20, # Use up to 4 concurrent threads/batches
            output_path_prefix="codeguru_partial_outputs/batch_", # Save partial results
            merge_output_path="final_codeguru_results.json", # Merge results
            delete_partials=False, # Keep partial files for inspection
            sleep_time_between_batches=1 # Small delay # FIXME 571 , 565/2104
        )

        end_time = time.time()
        print(f"\nAnalysis finished in {end_time - start_time:.2f} seconds.")

        if results:
            print(f"\nAnalysis complete. Findings merged into final_codeguru_results.json")
            print(f"Total findings: {len(results)}/{len(dummy_code_data)} items analyzed.")

            to_save = []
            for sample in raw_data:
                if sample["recordId"] in results:
                    continue
                to_save.append(sample)

            with open("final_refined_code.jsonl", 'w', encoding='utf-8') as f:
                for item in to_save:
                    json.dump(item, f)
                    f.write('\n')


            print(CodeGuruAnalyzer.analyse_results(results))
            # You can load and inspect the results here if needed
            # try:
            #     with open("final_codeguru_results.json", 'r') as f:
            #         final_findings = json.load(f) # json.load should work with ISO 8601 strings
            #     print(f"Loaded {len(final_findings)} records with findings from merged file.")
            #     # Example: Print findings for a specific record ID
            #     # print("\nFindings for 'code_sample_1':")
            #     # import pprint
            #     # pprint.pprint(final_findings.get('code_sample_1'))
            # except FileNotFoundError:
            #     print("Merged output file not found.")
            # except json.JSONDecodeError as e:
            #      print(f"Failed to decode merged output JSON: {e}")
        else:
            print("\nAnalysis completed but no findings were retrieved or merged.")
            print("Check logs for potential errors or if no vulnerabilities were found.")