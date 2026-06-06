#!/bin/bash
# Run vulnerability evaluation with CodeQL, OpenGrep (semgrep-compatible), and Bandit
# on all generations_* files.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="/home/kobzaond/Dokumenty/alquictCoder/cobot_venv2"
GENERATIONS_DIR="$SCRIPT_DIR/generations"
RESULTS_DIR="$SCRIPT_DIR/vuln_eval_results"

CODEQL_BIN="/home/kobzaond/Dokumenty/amazon2026/vulnerability_inspector/tmp/codeql/codeql"
OPENGREP_BIN="/home/kobzaond/Dokumenty/amazon2026/vulnerability_inspector/tmp/bin/opengrep"
SEMGREP_BIN="/home/kobzaond/miniconda3/bin/semgrep"

source "$VENV/bin/activate"
export PYTHONPATH="$SCRIPT_DIR/../codeguru-analyzer:$PYTHONPATH"

mkdir -p "$RESULTS_DIR/codeql" "$RESULTS_DIR/opengrep" "$RESULTS_DIR/bandit"

# Summary TSV files
CODEQL_TSV="$RESULTS_DIR/summary_codeql.tsv"
OPENGREP_TSV="$RESULTS_DIR/summary_opengrep.tsv"
BANDIT_TSV="$RESULTS_DIR/summary_bandit.tsv"

# Clear old summaries
> "$CODEQL_TSV"
> "$OPENGREP_TSV"
> "$BANDIT_TSV"

echo "=== Vulnerability Evaluation ==="
echo "Generations dir: $GENERATIONS_DIR"
echo ""

for GENFILE in "$GENERATIONS_DIR"/generations_*.jsonl; do
    BASENAME=$(basename "$GENFILE" .jsonl)
    echo "=========================================="
    echo "Processing: $BASENAME"
    echo "=========================================="

    # --- CodeQL ---
    echo "  [CodeQL] Running..."
    python "$SCRIPT_DIR/eval_vuln_with_codeql.py" \
        --generations-file "$GENFILE" \
        --codeql-bin "$CODEQL_BIN" \
        --ignore-severities "Low" \
        --output "$RESULTS_DIR/codeql/${BASENAME}.json" \
        --summary-tsv "$CODEQL_TSV" \
        --timeout 600 2>/dev/null || echo "  [CodeQL] FAILED for $BASENAME"

    # --- OpenGrep (semgrep-compatible) ---
    echo "  [OpenGrep] Running..."
    python "$SCRIPT_DIR/eval_vuln_with_semgrep.py" \
        --generations-file "$GENFILE" \
        --semgrep-bin "$OPENGREP_BIN" \
        --configs "p/security-audit,p/owasp-top-ten" \
        --ignore-severities "Low" \
        --output "$RESULTS_DIR/opengrep/${BASENAME}.json" \
        --summary-tsv "$OPENGREP_TSV" \
        --timeout 300 2>/dev/null || echo "  [OpenGrep] FAILED for $BASENAME"

    # --- Bandit ---
    echo "  [Bandit] Running..."
    python "$SCRIPT_DIR/eval_vuln_with_bandit_standalone.py" \
        --generations-file "$GENFILE" \
        --ignore-severities "LOW" \
        --output "$RESULTS_DIR/bandit/${BASENAME}.json" \
        --summary-tsv "$BANDIT_TSV" 2>/dev/null || echo "  [Bandit] FAILED for $BASENAME"

    echo ""
done

echo ""
echo "=========================================="
echo "=== SUMMARY ==="
echo "=========================================="
echo ""
echo "--- CodeQL Results ---"
echo "Model	Total	WithCode	Vulnerable	VulnRate	Accuracy	Findings"
cat "$CODEQL_TSV"
echo ""
echo "--- OpenGrep Results ---"
echo "Model	Total	WithCode	Vulnerable	VulnRate	Accuracy	Findings"
cat "$OPENGREP_TSV"
echo ""
echo "--- Bandit Results ---"
echo "Model	Total	WithCode	Vulnerable	VulnRate	Accuracy	Findings"
cat "$BANDIT_TSV"
