# eval_vuln_batch_inspector.py
#
# Evaluates multiple generation JSONL files in a single Inspector scan.
# Pushes all snippets at once with filenames encoding the source:
#   code_src/{gen_name}__{sanitized_id}.py
# One push, one scan, then splits findings back per generation file.

import argparse
import glob
import json
import logging
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def sanitize_id(s):
    return re.sub(r"[^\w.-]", "_", str(s))


def extract_python_blocks(text):
    if not isinstance(text, str) or not text:
        return []
    pattern = re.compile(r"```(?:python|py)\s*\n(.*?)```", re.IGNORECASE | re.DOTALL)
    blocks = pattern.findall(text)
    return [b.strip() for b in blocks if b and b.strip()]


def join_blocks(blocks):
    if not blocks:
        return ""
    if len(blocks) == 1:
        return blocks[0]
    return "\n\n# ===== cell separator =====\n\n".join(blocks)


def load_generations(path):
    data = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data.append(json.loads(line))
    return data


def main():
    parser = argparse.ArgumentParser(
        description="Batch evaluate all generation files via a single Inspector scan."
    )
    parser.add_argument(
        "--generations-dir", type=str, required=True,
        help="Directory containing generations_*.jsonl files.",
    )
    parser.add_argument(
        "--extra-files", type=str, nargs="*", default=[],
        help="Additional JSONL files outside the directory.",
    )
    parser.add_argument("--github-token", type=str, default=None)
    parser.add_argument("--region", type=str, default=None)
    parser.add_argument("--ignore-severities", type=str, default="Low,Info")
    parser.add_argument("--project-id", type=str, default=None)
    parser.add_argument("--repo", type=str, default=None)
    parser.add_argument(
        "--output-dir", type=str, default="inspector_results",
        help="Directory to save per-file results and summary.",
    )

    args = parser.parse_args()

    github_token = args.github_token or os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("Error: GitHub token required. Use --github-token or set $GITHUB_TOKEN.")
        return 1

    # Collect generation files
    gen_files = sorted(glob.glob(os.path.join(args.generations_dir, "generations_*.jsonl")))
    for ef in args.extra_files:
        if os.path.isfile(ef) and ef not in gen_files:
            gen_files.append(ef)

    if not gen_files:
        print(f"No generation files found in {args.generations_dir}")
        return 1

    print(f"Found {len(gen_files)} generation files.")

    # Build combined code_data with composite IDs: {gen_name}__{sanitized_id}
    # Also track the mapping: composite_id -> (gen_name, original_id)
    all_code_items = []
    composite_to_source = {}  # composite_id -> (gen_name, original_qid)
    gen_totals = {}  # gen_name -> (total_entries, entries_with_code)

    for gen_file in gen_files:
        gen_name = os.path.basename(gen_file).replace(".jsonl", "")
        entries = load_generations(gen_file)
        total_entries = len(entries)
        code_count = 0

        for entry in entries:
            qid = str(entry.get("id", ""))
            if not qid:
                continue

            code = entry.get("extracted_code", "")
            if not code or not code.strip():
                raw_answer = entry.get("raw_answer", "")
                blocks = extract_python_blocks(raw_answer)
                if blocks:
                    code = join_blocks(blocks)
                else:
                    code = raw_answer

            if not code or not code.strip():
                continue

            sid = sanitize_id(qid)
            composite_id = f"{sanitize_id(gen_name)}__{sid}"
            all_code_items.append({"id": composite_id, "code": code})
            composite_to_source[composite_id] = (gen_name, qid)
            code_count += 1

        gen_totals[gen_name] = (total_entries, code_count)
        print(f"  {gen_name}: {total_entries} entries, {code_count} with code")

    print(f"\nTotal snippets to scan: {len(all_code_items)}")

    if not all_code_items:
        print("No code found across any generation file.")
        return 1

    # Initialize analyzer
    from codeguru.inspector_analyzer import InspectorAnalyzer

    severities_to_ignore = set(
        s.strip() for s in args.ignore_severities.split(",") if s.strip()
    )
    analyzer = InspectorAnalyzer(
        github_token=github_token,
        repo_full_name=args.repo,
        region=args.region,
        severities_to_ignore=severities_to_ignore,
        project_id=args.project_id,
        cleanup_after_scan=True,
    )

    print(f"\nPushing {len(all_code_items)} snippets and running single Inspector scan...")
    results = analyzer.analyze_code(
        code_data=all_code_items,
    )

    if results is None:
        print("Inspector analysis failed.")
        return 1

    # Split results back per generation file
    per_gen_results = defaultdict(dict)  # gen_name -> {original_sid: [findings]}
    for composite_id, findings in results.items():
        if composite_id in composite_to_source:
            gen_name, original_qid = composite_to_source[composite_id]
            original_sid = sanitize_id(original_qid)
            per_gen_results[gen_name][original_sid] = findings

    # Save results and print summary
    os.makedirs(args.output_dir, exist_ok=True)
    summary_path = os.path.join(args.output_dir, "summary.tsv")

    with open(summary_path, "w", encoding="utf-8") as summary_f:
        summary_f.write("generation\ttotal\twith_code\tvulnerable\tvuln_rate\taccuracy\tfindings\n")

        print(f"\n{'='*80}")
        print(f"{'Generation':<50} {'Total':>5} {'Code':>5} {'Vuln':>5} {'Rate':>8} {'Findings':>8}")
        print(f"{'='*80}")

        for gen_name in sorted(gen_totals.keys()):
            total_entries, code_count = gen_totals[gen_name]
            gen_findings = per_gen_results.get(gen_name, {})

            vulnerable_count = len(gen_findings)
            total_findings = sum(len(v) for v in gen_findings.values())
            vuln_rate = vulnerable_count / total_entries if total_entries > 0 else 0.0
            accuracy = (code_count - vulnerable_count) / code_count if code_count > 0 else 0.0

            print(
                f"{gen_name:<50} {total_entries:>5} {code_count:>5} "
                f"{vulnerable_count:>5} {vuln_rate:>7.2%} {total_findings:>8}"
            )

            summary_f.write(
                f"{gen_name}\t{total_entries}\t{code_count}\t{vulnerable_count}\t"
                f"{vuln_rate:.4f}\t{accuracy:.4f}\t{total_findings}\n"
            )

            # Save per-gen results JSON
            result_path = os.path.join(args.output_dir, f"{gen_name}.json")
            with open(result_path, "w", encoding="utf-8") as f:
                json.dump(gen_findings, f, indent=2, default=str)

    print(f"{'='*80}")
    print(f"\nSummary saved to: {summary_path}")
    print(f"Per-file results in: {args.output_dir}/")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
