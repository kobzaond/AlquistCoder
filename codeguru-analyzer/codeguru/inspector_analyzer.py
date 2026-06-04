import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFORMATIONAL": "Info",
}

INTEGRATION_ARN = (
    "arn:aws:inspector2:us-east-1:980637428984:"
    "codesecurity-integration/156dfce3-c838-49b0-bb3d-1d7272d505dc"
)


def _aws_cli(*args, region="us-east-1") -> dict:
    cmd = ["aws"] + list(args) + ["--region", region, "--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"AWS CLI error: {error}")
    return json.loads(result.stdout) if result.stdout.strip() else {}


def _run_git(repo_dir, *args, timeout=120):
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    result = subprocess.run(
        ["git"] + list(args),
        cwd=repo_dir,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )
    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {error}")
    return result.stdout.strip()


class InspectorAnalyzer:
    """Analyzes code snippets using AWS Inspector Code Security.

    Uses a persistent GitHub repo as a scanning workspace: pushes snippets
    as .py files, triggers an Inspector scan, retrieves findings, then
    cleans up the files.

    The repo must be pre-connected to Inspector's GitHub App integration
    and must have been scanned at least once so that its project ID is
    discoverable via findings. Pass project_id explicitly to skip discovery.

    Prerequisites:
        - AWS CLI configured with inspector2 permissions
        - Inspector code security enabled with a GitHub integration
        - A persistent GitHub repo connected to Inspector
        - GitHub token with push access to the repo
    """

    DEFAULT_REGION = "us-east-1"
    MAX_POLL_ATTEMPTS = 180
    POLL_SLEEP_SECONDS = 10
    DEFAULT_SEVERITIES_TO_IGNORE = {"Low", "Info"}
    DEFAULT_RULE_SUBSTRINGS_TO_IGNORE = {"cdk", "debug-feature", "denylist"}
    DEFAULT_CODE_SUBDIR = "code_src"
    DEFAULT_REPO = "ATC26-alquist-develop/vuln-bench-scanner"

    def __init__(
        self,
        github_token,
        repo_full_name=None,
        region=None,
        severities_to_ignore=None,
        rule_substrings_to_ignore=None,
        code_subdir=DEFAULT_CODE_SUBDIR,
        include_raw=False,
        project_id=None,
        cleanup_after_scan=True,
    ):
        """
        Args:
            github_token: GitHub PAT with push access to the scanning repo.
            repo_full_name: Full name of the persistent scanning repo
                            (e.g. "org/repo"). Defaults to DEFAULT_REPO.
            region: AWS region for Inspector.
            severities_to_ignore: Set of severity strings to filter out.
            rule_substrings_to_ignore: Set of substrings; any rule_id
                containing one of these is skipped. Defaults to ignoring
                CDK, debug-feature, and denylist rules.
            code_subdir: Subdirectory within the repo for snippet files.
            include_raw: Include full raw finding in parsed output.
            project_id: Explicit Inspector project ID (skip discovery).
            cleanup_after_scan: Remove snippet files from repo after scan.
        """
        self.github_token = github_token
        self.repo_full_name = repo_full_name or self.DEFAULT_REPO
        self.region = region or self.DEFAULT_REGION
        self.severities_to_ignore = (
            severities_to_ignore
            if severities_to_ignore is not None
            else self.DEFAULT_SEVERITIES_TO_IGNORE
        )
        self.rule_substrings_to_ignore = (
            rule_substrings_to_ignore
            if rule_substrings_to_ignore is not None
            else self.DEFAULT_RULE_SUBSTRINGS_TO_IGNORE
        )
        self.code_subdir = code_subdir
        self.include_raw = include_raw
        self.project_id = project_id
        self.cleanup_after_scan = cleanup_after_scan

        owner_repo = self.repo_full_name.split("/")
        self.repo_owner = owner_repo[0]
        self.repo_name = owner_repo[1] if len(owner_repo) > 1 else owner_repo[0]

        self._verify_aws_inspector()

        if not self.project_id:
            self.project_id = self._find_project_id()
            if self.project_id:
                logger.info(f"Discovered project ID: {self.project_id}")
            else:
                logger.warning(
                    f"Could not discover project ID for {self.repo_full_name}. "
                    f"Will retry after pushing code."
                )

        self.integration_arn = self._get_integration_arn()

        logger.info(
            f"InspectorAnalyzer initialized: repo={self.repo_full_name}, "
            f"region={self.region}, project_id={self.project_id}, "
            f"ignore_severities={self.severities_to_ignore}"
        )

    def _verify_aws_inspector(self):
        try:
            status_data = _aws_cli(
                "inspector2", "batch-get-account-status", region=self.region
            )
            accounts = status_data.get("accounts", [])
            if accounts:
                code_status = (
                    accounts[0]
                    .get("resourceState", {})
                    .get("codeRepository", {})
                    .get("status", "DISABLED")
                )
                if code_status != "ENABLED":
                    raise RuntimeError(
                        f"Inspector code security is not enabled (status: {code_status}). "
                        f"Enable it in AWS Console -> Inspector -> Code security."
                    )
        except RuntimeError:
            raise
        except Exception as e:
            raise RuntimeError(f"Failed to verify Inspector status: {e}")

    def _find_project_id(self):
        """Find the Inspector project ID for the repo by searching findings."""
        target = f"{self.repo_owner}/{self.repo_name}"
        logger.info(f"Searching for project ID for {target}")

        next_token = None
        pages = 0
        while pages < 20:
            args = [
                "inspector2", "list-findings",
                "--filter-criteria", json.dumps({
                    "findingType": [
                        {"comparison": "EQUALS", "value": "CODE_VULNERABILITY"}
                    ],
                }),
                "--max-results", "100",
            ]
            if next_token:
                args += ["--next-token", next_token]

            try:
                data = _aws_cli(*args, region=self.region)
                for finding in data.get("findings", []):
                    for res in finding.get("resources", []):
                        details = res.get("details", {}).get("codeRepository", {})
                        project_name = details.get("projectName", "")
                        if project_name.startswith(target + ":") or project_name == target:
                            rid = res.get("id", "")
                            if "/project-" in rid:
                                return "project-" + rid.split("/project-")[1]
                next_token = data.get("nextToken")
                if not next_token:
                    break
                pages += 1
            except Exception as e:
                logger.warning(f"Error searching for project ID: {e}")
                break

        return None

    def _wait_for_project_id(self, max_attempts=30, sleep_between=10):
        """Wait for Inspector to discover the repo and produce findings."""
        for attempt in range(max_attempts):
            pid = self._find_project_id()
            if pid:
                return pid
            if attempt < max_attempts - 1:
                logger.info(
                    f"Project ID not found (attempt {attempt+1}/{max_attempts}), "
                    f"waiting {sleep_between}s..."
                )
                time.sleep(sleep_between)
        return None

    def _get_integration_arn(self):
        try:
            data = _aws_cli(
                "inspector2", "list-code-security-integrations",
                region=self.region,
            )
            integrations = data.get("integrations", [])
            if integrations:
                return integrations[0].get("integrationArn", "")
        except Exception as e:
            logger.warning(f"Failed to get integration ARN: {e}")
        return INTEGRATION_ARN

    def _clone_repo(self):
        """Clone the persistent repo. Returns (repo_dir, tmp_dir_path)."""
        auth_url = (
            f"https://x-access-token:{self.github_token}@github.com/"
            f"{self.repo_full_name}.git"
        )
        tmp_dir = tempfile.mkdtemp(prefix="inspector_scan_")
        repo_dir = os.path.join(tmp_dir, "repo")

        _run_git(tmp_dir, "clone", "--depth", "1", auth_url, "repo")
        _run_git(repo_dir, "config", "user.email", "inspector-analyzer@noreply")
        _run_git(repo_dir, "config", "user.name", "InspectorAnalyzer")

        return repo_dir, tmp_dir

    def _push_snippets(self, repo_dir, code_data):
        """Clear code_subdir, write snippet files, commit, push."""
        code_dir = os.path.join(repo_dir, self.code_subdir)

        # Clear existing snippet files
        if os.path.exists(code_dir):
            shutil.rmtree(code_dir)
        os.makedirs(code_dir, exist_ok=True)

        for item in code_data:
            record_id = item["id"]
            code = item["code"]
            sanitized = re.sub(r"[^\w.-]", "_", str(record_id))
            file_path = os.path.join(code_dir, f"{sanitized}.py")
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code)

        _run_git(repo_dir, "add", "-A")

        # Check if there are changes to commit
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_dir, capture_output=True, text=True,
        ).stdout.strip()
        if not status:
            logger.info("No changes to commit (snippets identical to last push)")
            return

        _run_git(
            repo_dir, "commit", "-m",
            f"Inspector scan: {len(code_data)} snippets",
        )
        _run_git(repo_dir, "push", "origin", "HEAD", timeout=300)
        logger.info(f"Pushed {len(code_data)} snippets to {self.repo_full_name}")

    def _cleanup_repo(self, repo_dir):
        """Remove snippet files from the repo after scanning."""
        code_dir = os.path.join(repo_dir, self.code_subdir)
        if not os.path.exists(code_dir):
            return

        shutil.rmtree(code_dir)
        os.makedirs(code_dir, exist_ok=True)
        # Keep directory with a .gitkeep
        with open(os.path.join(code_dir, ".gitkeep"), "w") as f:
            pass

        _run_git(repo_dir, "add", "-A")
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_dir, capture_output=True, text=True,
        ).stdout.strip()
        if not status:
            return

        _run_git(repo_dir, "commit", "-m", "Cleanup after scan")
        _run_git(repo_dir, "push", "origin", "HEAD", timeout=120)
        logger.info("Cleaned up snippet files from repo")

    def _start_scan(self, project_id):
        try:
            data = _aws_cli(
                "inspector2", "start-code-security-scan",
                "--resource", json.dumps({"projectId": project_id}),
                region=self.region,
            )
            scan_id = data.get("scanId")
            logger.info(f"Started scan {scan_id} for project {project_id}")
            return scan_id
        except Exception as e:
            logger.warning(f"Failed to start scan: {e}")
            return None

    def _poll_scan(self, project_id, scan_id):
        for attempt in range(self.MAX_POLL_ATTEMPTS):
            try:
                data = _aws_cli(
                    "inspector2", "get-code-security-scan",
                    "--resource", json.dumps({"projectId": project_id}),
                    "--scan-id", scan_id,
                    region=self.region,
                )
                status = data.get("status", "UNKNOWN")
                elapsed = (attempt + 1) * self.POLL_SLEEP_SECONDS
                logger.info(f"Scan {scan_id}: {status} ({elapsed}s)")
                if status not in ("IN_PROGRESS", "PENDING"):
                    return status
            except Exception as e:
                logger.warning(f"Poll error: {e}")

            time.sleep(self.POLL_SLEEP_SECONDS)

        return "TIMED_OUT"

    def _get_findings(self, resource_arn):
        all_findings = []
        next_token = None

        while True:
            args = [
                "inspector2", "list-findings",
                "--filter-criteria", json.dumps({
                    "findingType": [
                        {"comparison": "EQUALS", "value": "CODE_VULNERABILITY"}
                    ],
                    "resourceId": [
                        {"comparison": "EQUALS", "value": resource_arn}
                    ],
                }),
                "--max-results", "100",
            ]
            if next_token:
                args += ["--next-token", next_token]

            try:
                data = _aws_cli(*args, region=self.region)
                all_findings.extend(data.get("findings", []))
                next_token = data.get("nextToken")
                if not next_token:
                    break
            except Exception as e:
                logger.warning(f"Failed to get findings: {e}")
                break

        logger.info(f"Retrieved {len(all_findings)} raw findings")
        return all_findings

    def _parse_findings(self, raw_findings, expected_ids=None):
        """Parse Inspector findings into {sanitized_id: [finding_dicts]}.

        Maps findings back to snippet IDs using file paths.

        Args:
            raw_findings: List of raw Inspector finding dicts.
            expected_ids: Optional set of snippet IDs from the current push.
                          If provided, findings for IDs not in this set are
                          discarded (filters out stale findings from prior scans).
        """
        if not raw_findings:
            return {}

        parsed = defaultdict(list)
        skipped_stale = 0

        for f in raw_findings:
            severity_raw = f.get("severity", "MEDIUM")
            severity = SEVERITY_MAP.get(severity_raw.upper(), severity_raw)

            if severity in self.severities_to_ignore:
                continue

            vuln = f.get("codeVulnerabilityDetails", {})

            rule_id = vuln.get("ruleId", "")
            if self.rule_substrings_to_ignore and any(
                sub in rule_id for sub in self.rule_substrings_to_ignore
            ):
                continue

            file_info = vuln.get("filePath", {})
            file_path_str = file_info.get("filePath", "")

            record_id = Path(file_path_str).stem
            if not record_id:
                logger.warning(f"Could not extract record ID from path: {file_path_str}")
                continue

            if expected_ids is not None and record_id not in expected_ids:
                skipped_stale += 1
                continue

            remediation = f.get("remediation", {})
            recommendation = remediation.get("recommendation", {})
            cwes = vuln.get("cwes", [])
            cwe_list = [c if c.startswith("CWE-") else f"CWE-{c}" for c in cwes]

            start_line = file_info.get("startLine", 0)
            end_line = file_info.get("endLine", 0)

            snippet_lines = file_info.get("codeSnippet", [])
            code_snippet = "\n".join(
                line_info.get("content", "") for line_info in snippet_lines
            )

            vulnerable_lines = []
            if start_line and end_line:
                for line_info in snippet_lines:
                    ln = line_info.get("number", 0)
                    if isinstance(ln, int) and start_line <= ln <= end_line:
                        vulnerable_lines.append(line_info.get("content", ""))

            finding_dict = {
                "title": f.get("title", ""),
                "severity": severity,
                "description": f.get("description", "")[:500],
                "recommendation": recommendation.get("text", "")[:500],
                "code_snippet": code_snippet.strip(),
                "vulnerable_part": "\n".join(vulnerable_lines).strip(),
                "rule_id": vuln.get("ruleId", ""),
                "cwes": cwe_list,
                "detector": vuln.get("detectorName", ""),
            }

            if self.include_raw:
                finding_dict["raw_finding"] = f

            parsed[record_id].append(finding_dict)

        if skipped_stale:
            logger.info(f"Skipped {skipped_stale} stale findings from prior scans")
        logger.info(f"Parsed findings for {len(parsed)} records")
        return dict(parsed)

    def analyze_code(
        self,
        code_data,
        max_batch_items=None,
        max_batch_uncompressed_size_mb=None,
        max_workers=None,
        output_path_prefix=None,
        merge_output_path=None,
        delete_partials=True,
        sleep_time_between_batches=None,
    ):
        """Analyze code snippets via AWS Inspector.

        Interface-compatible with CodeGuruAnalyzer.analyze_code.
        CodeGuru-specific kwargs are accepted but ignored.

        Args:
            code_data: list of {"id": str, "code": str} dicts.

        Returns:
            dict mapping sanitized IDs to lists of finding dicts,
            or None on failure.
        """
        if not code_data:
            logger.warning("No code data provided.")
            return {}

        for item in code_data:
            if "id" not in item or "code" not in item:
                logger.error(f"Invalid item (missing id or code): {item}")
                return None

        tmp_dir = None
        repo_dir = None

        try:
            # 1. Clone repo and push snippets
            repo_dir, tmp_dir = self._clone_repo()
            self._push_snippets(repo_dir, code_data)

            # 2. Find project ID if not yet known
            if not self.project_id:
                logger.info(
                    "Project ID not known. Waiting for Inspector to scan "
                    "the repo via push event..."
                )
                self.project_id = self._wait_for_project_id()

            if not self.project_id:
                logger.error(
                    f"Could not find Inspector project ID for {self.repo_full_name}. "
                    f"Ensure the repo is connected to Inspector's GitHub App and "
                    f"has been scanned at least once."
                )
                return None

            # 3. Start on-demand scan
            scan_id = self._start_scan(self.project_id)
            if scan_id:
                final_status = self._poll_scan(self.project_id, scan_id)
                logger.info(f"Scan completed: {final_status}")
                if final_status not in ("SUCCESSFUL", "Successful"):
                    logger.warning(f"Scan status: {final_status}")
            else:
                logger.info("Could not start scan, will fetch existing findings")

            # 4. Retrieve findings
            resource_arn = ""
            if self.integration_arn:
                resource_arn = f"{self.integration_arn}/{self.project_id}"

            expected_ids = {
                re.sub(r"[^\w.-]", "_", str(item["id"])) for item in code_data
            }

            raw_findings = self._get_findings(resource_arn)
            results = self._parse_findings(raw_findings, expected_ids=expected_ids)

            # 5. Save results
            if merge_output_path:
                try:
                    Path(merge_output_path).parent.mkdir(parents=True, exist_ok=True)
                    with open(merge_output_path, "w", encoding="utf-8") as f:
                        json.dump(results, f, indent=4, default=str)
                    logger.info(f"Results saved to {merge_output_path}")
                except Exception as e:
                    logger.error(f"Failed to save results: {e}")

            # 6. Cleanup repo
            if self.cleanup_after_scan and repo_dir:
                try:
                    self._cleanup_repo(repo_dir)
                except Exception as e:
                    logger.warning(f"Failed to cleanup repo: {e}")

            return results

        except Exception as e:
            logger.error(f"Inspector analysis failed: {e}", exc_info=True)
            return None

        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)

    @staticmethod
    def analyse_results(res_dict):
        """Count unique vulnerabilities per file.

        Identical to CodeGuruAnalyzer.analyse_results.
        """
        vulnerability_counts = defaultdict(int)
        for file_key, findings_list in res_dict.items():
            seen = set()
            for finding in findings_list:
                title = finding.get("title")
                if title and title not in seen:
                    seen.add(title)
                    vulnerability_counts[title] += 1
        sorted_items = sorted(
            vulnerability_counts.items(), key=lambda x: x[1], reverse=True
        )
        return dict(sorted_items)
