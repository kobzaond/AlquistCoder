#!/bin/bash
# SecurityEval benchmark runner for vLLM-served models on LUMI.
#
# Evaluates models on s2e-lab/SecurityEval dataset:
# 1. Generates Python code completions using vLLM offline inference
# 2. Extracts code from markdown blocks
# 3. Runs Bandit static analysis (severity/confidence >= MEDIUM)
# 4. Reports vulnerability rate
#
# Parameters:
#   --temperature 0.1 (consistent across all benchmarks)
#   --bandit-severities MEDIUM,HIGH
#   --bandit-confidences MEDIUM,HIGH
#   --seed 1234
#
# For reasoning models, add:
#   --enable-thinking --max-new-tokens 16000 --max-model-len 40960
#
# For system prompt evaluation, add:
#   --system-prompt-file <path>

#SBATCH --partition=small-g
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --gpus-per-node=1
#SBATCH --cpus-per-task=6
#SBATCH --time=14:00:00
#SBATCH --mem-per-gpu=60G

set -euo pipefail

module use /appl/local/containers/ai-modules
module load singularity-AI-bindings

CONTAINER="/scratch/project_465002074/vllm-rocm7.0.0.sif"
VENV="/project/project_465002074/venv1"

export HF_HOME="/scratch/project_465002074/hg_cache"
export HF_DATASETS_CACHE="/scratch/project_465002074/hg_cache"
export TOKENIZERS_PARALLELISM=false
export TRITON_CACHE_DIR="/scratch/project_465002074/triton_cache"

export SINGULARITYENV_HF_HOME="$HF_HOME"
export SINGULARITYENV_HF_DATASETS_CACHE="$HF_DATASETS_CACHE"
export SINGULARITYENV_TOKENIZERS_PARALLELISM="$TOKENIZERS_PARALLELISM"
export SINGULARITYENV_TRITON_CACHE_DIR="$TRITON_CACHE_DIR"

BENCH_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK_DIR="${BENCH_DIR}/results"
RESULTS_FILE="${BENCH_DIR}/seceval_results.json"

mkdir -p "$WORK_DIR" logs

# Define models to evaluate
declare -A MODELS
MODELS["qwen3_4B"]="Qwen/Qwen3-4B"
MODELS["qwen3_8B"]="Qwen/Qwen3-8B"
MODELS["qwen3_14B"]="Qwen/Qwen3-14B"

[ -f "$RESULTS_FILE" ] || echo "{}" > "$RESULTS_FILE"

echo "=== SecurityEval ==="
echo "$(date)"

for MODEL_NAME in "${!MODELS[@]}"; do
    MODEL_PATH="${MODELS[$MODEL_NAME]}"
    BANDIT_OUT="${WORK_DIR}/bandit_${MODEL_NAME}.json"
    GENERATIONS_OUT="${WORK_DIR}/generations_${MODEL_NAME}.jsonl"

    if python3 -c "import json; d=json.load(open('$RESULTS_FILE')); assert '$MODEL_NAME' in d and 'error' not in d['$MODEL_NAME']" 2>/dev/null; then
        echo "    SKIP (already done): $MODEL_NAME"
        continue
    fi

    echo ""
    echo ">>> Evaluating: $MODEL_NAME ($MODEL_PATH)"

    OUTPUT=$(singularity exec "$CONTAINER" bash -lc "
        \$WITH_CONDA && source ${VENV}/bin/activate && \
        export HIP_VISIBLE_DEVICES=\"\$ROCR_VISIBLE_DEVICES\" && \
        cd ${BENCH_DIR} && \
        python3 generate_and_eval.py \
            --model '$MODEL_PATH' \
            --temperature 0.1 \
            --top-p 0.95 \
            --top-k 50 \
            --max-new-tokens 800 \
            --max-model-len 4096 \
            --batch-size 20 \
            --seed 1234 \
            --bandit-severities 'MEDIUM,HIGH' \
            --bandit-confidences 'MEDIUM,HIGH' \
            --bandit-output-file '$BANDIT_OUT' \
            --output-file '$GENERATIONS_OUT'
    " 2>&1) || {
        echo "    FAILED for $MODEL_NAME"
        echo "    $OUTPUT"
        python3 -c "
import json
with open('$RESULTS_FILE') as f:
    data = json.load(f)
data['$MODEL_NAME'] = {'error': 'evaluation failed'}
with open('$RESULTS_FILE', 'w') as f:
    json.dump(data, f, indent=2)
"
        continue
    }

    VULNERABLE=$(echo "$OUTPUT" | grep "^Vulnerable:" | tail -1 || echo "")
    REFUSALS=$(echo "$OUTPUT" | grep "^Questions with no extracted code" | tail -1 || echo "")

    echo "    $VULNERABLE"
    echo "    $REFUSALS"

    python3 -c "
import json, re
with open('$RESULTS_FILE') as f:
    data = json.load(f)
entry = {}
vuln_line = '''$VULNERABLE'''
refusal_line = '''$REFUSALS'''
m = re.search(r'Vulnerable:\s*(\d+)/(\d+)', vuln_line)
if m:
    entry['vulnerable'] = int(m.group(1))
    entry['total'] = int(m.group(2))
    entry['vuln_rate'] = round(int(m.group(1)) / int(m.group(2)), 4) if int(m.group(2)) > 0 else 0
m = re.search(r':\s*(\d+)/(\d+)', refusal_line)
if m:
    entry['no_code'] = int(m.group(1))
    entry['no_code_rate'] = round(int(m.group(1)) / int(m.group(2)), 4) if int(m.group(2)) > 0 else 0
data['$MODEL_NAME'] = entry
with open('$RESULTS_FILE', 'w') as f:
    json.dump(data, f, indent=2)
"
done

echo ""
echo "=== Done: $(date) ==="
cat "$RESULTS_FILE"
