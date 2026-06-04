#!/usr/bin/env python3
"""Run CodeQL, OpenGrep, and Bandit evaluations on all generations_* files."""

import glob
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
GENERATIONS_DIR = SCRIPT_DIR / "generations"
RESULTS_DIR = SCRIPT_DIR / "vuln_eval_results"

CODEQL_BIN = "/home/kobzaond/Dokumenty/amazon2026/vulnerability_inspector/tmp/codeql/codeql"
OPENGREP_BIN = "/home/kobzaond/Dokumenty/amazon2026/vulnerability_inspector/tmp/bin/opengrep"

PYTHONPATH = f"{SCRIPT_DIR.parent / 'codeguru-analyzer'}:{os.environ.get('PYTHONPATH', '')}"


def run_eval(tool, genfile, extra_args):
    basename = Path(genfile).stem
    env = os.environ.copy()
    env["PYTHONPATH"] = PYTHONPATH

    if tool == "codeql":
        cmd = [
            sys.executable, str(SCRIPT_DIR / "eval_vuln_with_codeql.py"),
            "--generations-file", genfile,
            "--codeql-bin", CODEQL_BIN,
            "--ignore-severities", "Low",
            "--output", str(RESULTS_DIR / "codeql" / f"{basename}.json"),
            "--summary-tsv", str(RESULTS_DIR / "summary_codeql.tsv"),
            "--timeout", "600",
        ]
    elif tool == "opengrep":
        cmd = [
            sys.executable, str(SCRIPT_DIR / "eval_vuln_with_semgrep.py"),
            "--generations-file", genfile,
            "--semgrep-bin", OPENGREP_BIN,
            "--configs", "p/security-audit,p/owasp-top-ten",
            "--ignore-severities", "Low",
            "--output", str(RESULTS_DIR / "opengrep" / f"{basename}.json"),
            "--summary-tsv", str(RESULTS_DIR / "summary_opengrep.tsv"),
            "--timeout", "300",
        ]
    elif tool == "bandit":
        cmd = [
            sys.executable, str(SCRIPT_DIR / "eval_vuln_with_bandit_standalone.py"),
            "--generations-file", genfile,
            "--ignore-severities", "LOW",
            "--output", str(RESULTS_DIR / "bandit" / f"{basename}.json"),
            "--summary-tsv", str(RESULTS_DIR / "summary_bandit.tsv"),
        ]
    else:
        return f"Unknown tool: {tool}"

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=700, env=env)
        output = result.stdout
        if result.returncode != 0:
            output += f"\nSTDERR: {result.stderr[-500:]}"
        return f"[{tool}] {basename}: {output.strip().split(chr(10))[-5:]}"
    except subprocess.TimeoutExpired:
        return f"[{tool}] {basename}: TIMEOUT"
    except Exception as e:
        return f"[{tool}] {basename}: ERROR {e}"


def main():
    for subdir in ["codeql", "opengrep", "bandit"]:
        (RESULTS_DIR / subdir).mkdir(parents=True, exist_ok=True)

    # Clear summary files
    for tsv in ["summary_codeql.tsv", "summary_opengrep.tsv", "summary_bandit.tsv"]:
        (RESULTS_DIR / tsv).write_text("")

    gen_files = sorted(glob.glob(str(GENERATIONS_DIR / "generations_*.jsonl")))
    print(f"Found {len(gen_files)} generation files")
    print(f"Running 3 tools x {len(gen_files)} files = {3*len(gen_files)} evaluations")
    print()

    tasks = []
    for gf in gen_files:
        for tool in ["bandit", "opengrep", "codeql"]:
            tasks.append((tool, gf))

    # Run with limited parallelism (CodeQL is memory-heavy)
    with ProcessPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(run_eval, tool, gf, None): (tool, gf) for tool, gf in tasks}
        done = 0
        for future in as_completed(futures):
            done += 1
            result = future.result()
            # Print last few lines only
            lines = result.split("\n")
            summary_lines = [l for l in lines if "Vulnerable:" in l or "Accuracy" in l or "rate" in l or "FAILED" in l or "TIMEOUT" in l or "ERROR" in l]
            tool, gf = futures[future]
            basename = Path(gf).stem
            if summary_lines:
                print(f"[{done}/{len(tasks)}] [{tool}] {basename}: {summary_lines[0]}")
            else:
                print(f"[{done}/{len(tasks)}] [{tool}] {basename}: done")

    print("\n\nDone! Results in:", RESULTS_DIR)


if __name__ == "__main__":
    main()
