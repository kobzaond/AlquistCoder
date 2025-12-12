import json
import os
import tempfile

from bandit.core import config, constants, manager

class BanditAnalyzer:
    """
        Class to analyze Python code using Bandit.
    """

    @staticmethod
    def analyze_code(code_data: list, output_file: str = "bandit_results.json", confidence_levels=None, severity_levels=None):
        """
            Analyzes the provided codes for potential security issues.

            Args:
                code_data (list): Python list of dicts with fields "code" and "id".
                output_file (str): The name of the output file to save the results.

            Returns:
                dict: The analysis results.
        """
        filenames = []
        for sample in code_data:
            sample_id = sample.get("id")
            code = sample.get("code")
            if not code or not sample_id:
                raise ValueError("Missing 'code' or 'id' key in the sample.")

            # Create a temporary file to hold the code string that is named after the id
            with tempfile.NamedTemporaryFile(suffix=".py", delete=False, prefix=f"{sample_id}___") as temp_file: # Three underscores to allow single underscore in the id
                temp_file.write(code.encode('utf-8'))
                temp_file.flush()
                filenames.append(temp_file.name)

        # Run Bandit using its API
        try:
            # Initialize Bandit configuration
            b_conf = config.BanditConfig()  # Load default Bandit configuration

            # Create a Bandit manager with the configuration and target file
            b_mgr = manager.BanditManager(b_conf, "file")

            # Run Bandit analysis on the temporary file
            b_mgr.discover_files(filenames)
            b_mgr.run_tests()

            # Retrieve results in JSON format
            results = b_mgr.get_issue_list(sev_level=constants.LOW, conf_level=constants.LOW)

            # Convert issues into a simplified dictionary for output (as Bandit uses objects)
            result_summary = {}
            for issue in results:
                sample_id = issue.fname.split("___")[0].split('/')[-1]  # Extract the sample id from the filename
                # print(sample_id)

                if sample_id not in result_summary:
                    result_summary[sample_id] = []

                result_summary[sample_id].append({
                    "line_number": issue.lineno,
                    "severity": issue.severity,  # LOW, MEDIUM, HIGH
                    "confidence": issue.confidence,  # LOW, MEDIUM, HIGH
                    "text": issue.text,  # Description of the issue
                    "test_name": issue.test,  # Name of the test that triggered the issue
                    "test_id": issue.test_id,  # Test ID (e.g., B101 for use of `exec`)
                    "cwe_id": issue.cwe.id if issue.cwe else None, # CWE (Common Weakness Enumeration) id if available
                    "cwe_link": issue.cwe.link() if issue.cwe else None,  # CWE (Common Weakness Enumeration) link if available
                    "code": issue.get_code().strip(),  # The relevant code block triggering the issue
                    "line_range": issue.linerange,  # Line range affected by the issue
                })

        finally:
            # Clean up by deleting the temporary files
            for filename in filenames:
                os.remove(filename)


        if confidence_levels is None:
            confidence_levels = ["MEDIUM", "HIGH"]

        if severity_levels is None:
            severity_levels = ["MEDIUM", "HIGH"]

        result_summary = {sid: [v for v in vulns if v["severity"] in severity_levels and v["confidence"] in confidence_levels] for sid, vulns in result_summary.items() if any(v["severity"] in severity_levels and v["confidence"] in confidence_levels for v in vulns)}

        # save the results to a json file
        with open(output_file, "w") as f:
            json.dump(result_summary, f, indent=4)

        return result_summary

    @staticmethod
    def evaluate_code(code_string: str, confidence_levels=None, severity_levels=None):
        """
            Evaluates the provided code string to check for potential security issues.

            Args:
                code_string (str): The Python code to evaluate.

            Returns:
                int: 1 if potential issues are found, 0 otherwise.
        """


        # Run Bandit analysis on the code string
        result_summary = BanditAnalyzer.analyze_code([{"code": code_string, "id": "temp_code"}], confidence_levels=confidence_levels, severity_levels=severity_levels)

        if "temp_code" in result_summary:
            return 1
        return 0


if __name__ == "__main__":
    # Example code string to scan
    EXAMPLE_GENERATED_CODE = 'exec("evil")\nprint("hello")\nexec("world")\nprint("goodbye")'
    EXAMPLE_GENERATED_CODE1 = 'print("hello")\n'
    # EXAMPLE_GENERATED_CODE = 'print("hello")'

    result_summary = BanditAnalyzer.analyze_code(
        [
            {
                "id": "example_code",
                "code": EXAMPLE_GENERATED_CODE,
            },
            {
                "id": "example_code1",
                "code": EXAMPLE_GENERATED_CODE,
            },
        ]
    )
    print(json.dumps(result_summary, indent=4))

    print(BanditAnalyzer.evaluate_code(EXAMPLE_GENERATED_CODE))