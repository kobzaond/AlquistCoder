#!/usr/bin/env bash
set -euo pipefail

# Batch runner: evaluate all generation JSONL files with AWS Inspector.
# Usage: ./run_all_inspector.sh [--github-token TOKEN]
#
# Requires: GITHUB_TOKEN env var or --github-token argument
# Results are saved to: ./inspector_results/

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
GENERATION_DIR="/home/kobzaond/Dokumenty/amazon2026/generation"
EXTRA_FILE="/home/kobzaond/Dokumenty/amazon2026/generations_sft2__checkpoint-1000.jsonl"
OUTPUT_DIR="${SCRIPT_DIR}/inspector_results"
PROJECT_ID="project-69c2f59f-c8be-4718-8af0-337d41f2e567"
REGION="us-east-1"
IGNORE_SEVERITIES="Low,Info"

GITHUB_TOKEN="${GITHUB_TOKEN:-}"

# Parse args
while [[ $# -gt 0 ]]; do
    case $1 in
        --github-token) GITHUB_TOKEN="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

if [[ -z "$GITHUB_TOKEN" ]]; then
    echo "Error: GITHUB_TOKEN not set. Use --github-token or export GITHUB_TOKEN."
    exit 1
fi

export GITHUB_TOKEN

mkdir -p "$OUTPUT_DIR"

# Collect all generation JSONL files
FILES=()
if [[ -f "$EXTRA_FILE" ]]; then
    FILES+=("$EXTRA_FILE")
fi
for f in "$GENERATION_DIR"/generations_*.jsonl; do
    [[ -f "$f" ]] && FILES+=("$f")
done

echo "Found ${#FILES[@]} generation files to evaluate."
echo "Results will be saved to: $OUTPUT_DIR"
echo "---"

SUMMARY_FILE="$OUTPUT_DIR/summary.tsv"
echo -e "file\ttotal\twith_code\tvulnerable\tvuln_rate\taccuracy" > "$SUMMARY_FILE"

PASSED=0
FAILED=0

for GEN_FILE in "${FILES[@]}"; do
    BASENAME="$(basename "$GEN_FILE" .jsonl)"
    RESULT_FILE="$OUTPUT_DIR/${BASENAME}.json"

    echo ""
    echo "=== Processing: $BASENAME ==="

    if python3 "$SCRIPT_DIR/eval_vuln_with_inspector.py" \
        --generations-file "$GEN_FILE" \
        --github-token "$GITHUB_TOKEN" \
        --region "$REGION" \
        --ignore-severities "$IGNORE_SEVERITIES" \
        --project-id "$PROJECT_ID" \
        --output "$RESULT_FILE" \
        --summary-tsv "$SUMMARY_FILE" \
        2>&1 | tee /dev/stderr | tail -5; then
        PASSED=$((PASSED + 1))
    else
        echo "FAILED: $BASENAME"
        FAILED=$((FAILED + 1))
    fi
done

echo ""
echo "=== Done ==="
echo "Passed: $PASSED / $((PASSED + FAILED))"
echo "Failed: $FAILED / $((PASSED + FAILED))"
echo "Results in: $OUTPUT_DIR"
echo "Summary: $SUMMARY_FILE"
