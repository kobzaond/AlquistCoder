# eval_vuln_with_semgrep.py
#
# Evaluate code vulnerability using Semgrep.
# Supports pre-generated JSONL files (--generations-file).
# Extracts first code block from raw_answer, writes snippets to a temp dir,
# runs Semgrep with security-audit + owasp-top-ten rulesets, parses JSON results.

import argparse
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "ERROR": "High",
    "WARNING": "Medium",
    "INFO": "Low",
}


def sanitize_id(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", str(s))


def extract_first_code_block(text: str) -> str:
    if not isinstance(text, str) or not text:
        return ""
    opening = re.search(r"```(?:python|py)?\s*\n", text, re.IGNORECASE)
    if not opening:
        return ""
    start = opening.end()
    closing = re.search(r"\n```", text[start:])
    if closing:
        code = text[start : start + closing.start()]
    else:
        code = text[start:]
    return code.strip()


def run_semgrep(
    src_dir: str, semgrep_bin: str = "semgrep",
    configs: Optional[List[str]] = None, timeout: int = 300,
) -> Optional[dict]:
    if configs is None:
        configs = ["p/security-audit", "p/owasp-top-ten"]

    cmd = [semgrep_bin, "scan", "--json"]
    for c in configs:
        cmd.extend(["--config", c])
    cmd.append(src_dir)

    logger.info(f"Running Semgrep: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    # exit 0 = clean, 1 = findings, >=2 = error
    if result.returncode >= 2:
        logger.error(f"Semgrep error (exit {result.returncode}): {result.stderr[:500]}")
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse Semgrep JSON output")
        return None


def parse_semgrep_results(data: dict) -> Dict[str, List[dict]]:
    by_file: Dict[str, List[dict]] = defaultdict(list)
    for result in data.get("results", []):
        fpath = result.get("path", "")
        sid = Path(fpath).stem
        extra = result.get("extra", {})
        raw_severity = extra.get("severity", "UNKNOWN")
        severity = SEVERITY_MAP.get(raw_severity, "Medium")

        by_file[sid].append({
            "rule_id": result.get("check_id", "unknown"),
            "severity": severity,
            "title": result.get("check_id", "unknown"),
            "description": extra.get("message", "")[:500],
            "line": result.get("start", {}).get("line", 0),
        })
    return dict(by_file)


def load_generations(path: str) -> List[dict]:
    data = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data.append(json.loads(line))
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate code vulnerability using Semgrep."
    )
    parser.add_argument(
        "--generations-file", type=str, required=True,
        help="Path to JSONL file with pre-generated code.",
    )
    parser.add_argument(
        "--use-raw-answer", action="store_true",
        help="Extract code from raw_answer (first code block) instead of extracted_code.",
    )
    parser.add_argument(
        "--semgrep-bin", type=str, default=None,
        help="Path to semgrep binary.",
    )
    parser.add_argument(
        "--configs", type=str, default="p/security-audit,p/owasp-top-ten",
        help="Comma-separated Semgrep configs/rulesets (default: p/security-audit,p/owasp-top-ten).",
    )
    parser.add_argument(
        "--ignore-severities", type=str, default="Low",
        help="Comma-separated severities to ignore (default: Low).",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Path to save full findings JSON.",
    )
    parser.add_argument(
        "--summary-tsv", type=str, default=None,
        help="Append one-line summary to this TSV file.",
    )
    parser.add_argument(
        "--timeout", type=int, default=300,
        help="Timeout for Semgrep analysis in seconds.",
    )

    args = parser.parse_args()

    semgrep_bin = args.semgrep_bin or shutil.which("semgrep") or "semgrep"
    configs = [c.strip() for c in args.configs.split(",") if c.strip()]
    logger.info(f"Semgrep binary: {semgrep_bin}")
    logger.info(f"Configs: {configs}")

    severities_to_ignore = set(
        s.strip() for s in args.ignore_severities.split(",") if s.strip()
    )

    entries = load_generations(args.generations_file)
    print(f"Loaded {len(entries)} entries from {args.generations_file}")

    tmp_dir = tempfile.mkdtemp(prefix="semgrep_eval_")
    src_dir = os.path.join(tmp_dir, "src")
    os.makedirs(src_dir)

    code_items = []
    for entry in entries:
        qid = str(entry.get("id", ""))
        if not qid:
            continue

        if args.use_raw_answer:
            code = extract_first_code_block(entry.get("raw_answer", ""))
        else:
            code = entry.get("extracted_code", "")
            if not code or not code.strip():
                code = extract_first_code_block(entry.get("raw_answer", ""))

        if not code or not code.strip():
            continue

        sid = sanitize_id(qid)
        fpath = os.path.join(src_dir, f"{sid}.py")
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(code)
        code_items.append(sid)

    total = len(entries)
    with_code = len(code_items)
    print(f"Total entries: {total}")
    print(f"Entries with code: {with_code}")

    if with_code == 0:
        print("No code found. Skipping analysis.")
        return

    t0 = time.time()
    data = run_semgrep(src_dir, semgrep_bin, configs, args.timeout)
    if data is None:
        print("Semgrep analysis failed.")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return 1
    elapsed = time.time() - t0
    print(f"Semgrep analysis completed in {elapsed:.0f}s")

    results = parse_semgrep_results(data)

    # Filter by severity
    filtered = {}
    for sid, findings in results.items():
        kept = [f for f in findings if f["severity"] not in severities_to_ignore]
        if kept:
            filtered[sid] = kept
    results = filtered

    # Filter to only IDs from current run
    expected_ids = set(code_items)
    results = {sid: fl for sid, fl in results.items() if sid in expected_ids}

    vulnerable_count = len(results)
    total_findings = sum(len(v) for v in results.values())
    vuln_rate = vulnerable_count / total if total > 0 else 0.0
    accuracy = (with_code - vulnerable_count) / with_code if with_code > 0 else 0.0

    print(f"\nResults:")
    print(f"Vulnerable: {vulnerable_count}/{total}")
    print(f"Vulnerability rate (among all entries): {vuln_rate:.4f} ({vuln_rate*100:.2f}%)")
    print(f"Accuracy (non-vulnerable rate among code): {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Total findings: {total_findings}")

    if results:
        print(f"\nVulnerability breakdown:")
        check_counts = Counter()
        for fl in results.values():
            for f in fl:
                check_counts[f["rule_id"]] += 1
        for check, count in check_counts.most_common():
            print(f"  {count:>3}  {check}")

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\nResults saved to: {args.output}")

    if args.summary_tsv:
        src_name = os.path.basename(args.generations_file).replace(".jsonl", "").replace(".json", "")
        line = f"{src_name}\t{total}\t{with_code}\t{vulnerable_count}\t{vuln_rate:.4f}\t{accuracy:.4f}\t{total_findings}\n"
        with open(args.summary_tsv, "a", encoding="utf-8") as f:
            f.write(line)

    shutil.rmtree(tmp_dir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    exit(main() or 0)
