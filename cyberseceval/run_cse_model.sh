#!/bin/bash
# Reusable CyberSecEval runner. Expects env vars:
#   MODEL_PATH     - path or HF name of model to test
#   MODEL_NAME     - short name for output files
#   NUM_GPUS       - tensor parallel size (default 1)
#   MAX_MODEL_LEN  - vLLM max model length (default 4096)
#   EXTRA_VLLM_ARGS - additional vLLM args (optional)
#   SKIP_MITRE     - set to 1 to skip MITRE benchmarks
#   COT_END_TOKENS - set to e.g. '</think>' for reasoning models
#   OPENAI_API_KEY - for MITRE judge (GPT-4)
#
# NOTE: CyberSecEval uses PurpleLlama's DEFAULT_TEMPERATURE = 0.6 for all
# models (set inside the framework). This is consistent across all evaluated
# models. SecurityEval, VulnBench, and MalBench use temperature = 0.1.

set -euo pipefail

module use /appl/local/containers/ai-modules
module load singularity-AI-bindings

CONTAINER="/scratch/project_465002074/vllm-rocm7.0.0.sif"
VENV_VLLM="/project/project_465002074/venv1"
VENV_CSE="/project/project_465002074/venv_cse"

export HF_HOME="/scratch/project_465002074/hg_cache"
export HF_DATASETS_CACHE="/scratch/project_465002074/hg_cache"
export TOKENIZERS_PARALLELISM=false
export TRITON_CACHE_DIR="/scratch/project_465002074/triton_cache"

export HF_TOKEN=""  # set your HF token

export SINGULARITYENV_HF_HOME="$HF_HOME"
export SINGULARITYENV_HF_DATASETS_CACHE="$HF_DATASETS_CACHE"
export SINGULARITYENV_TOKENIZERS_PARALLELISM="$TOKENIZERS_PARALLELISM"
export SINGULARITYENV_TRITON_CACHE_DIR="$TRITON_CACHE_DIR"
export SINGULARITYENV_HF_TOKEN="$HF_TOKEN"

PURPLE="/pfs/lustrep1/users/kobzaond/PurpleLlama"
DATASETS="$PURPLE/CybersecurityBenchmarks/datasets"
CSE_DIR="/pfs/lustrep1/users/kobzaond/benchmarks/cyberseceval"
RESULTS_DIR="${CSE_DIR}/results/${MODEL_NAME}"
PORT=$(( 8000 + (SLURM_JOB_ID % 1000) ))
NUM_GPUS="${NUM_GPUS:-1}"
MAX_MODEL_LEN="${MAX_MODEL_LEN:-4096}"
EXTRA_VLLM_ARGS="${EXTRA_VLLM_ARGS:-}"
SKIP_MITRE="${SKIP_MITRE:-0}"
COT_END_TOKENS="${COT_END_TOKENS:-}"

mkdir -p "$RESULTS_DIR"

echo "=== CyberSecEval: $MODEL_NAME ==="
echo "Model: $MODEL_PATH"
echo "GPUs: $NUM_GPUS, MaxLen: $MAX_MODEL_LEN"
echo "Results: $RESULTS_DIR"
echo ""

cleanup_vllm() {
    echo ">>> Stopping vLLM server..."
    kill $VLLM_PID 2>/dev/null || true
    wait $VLLM_PID 2>/dev/null || true
}

# --- Step 1: Start vLLM server ---
echo ">>> Starting vLLM server..."
singularity exec "$CONTAINER" bash -lc "
    \$WITH_CONDA && source ${VENV_VLLM}/bin/activate && \
    export HIP_VISIBLE_DEVICES=\"\$ROCR_VISIBLE_DEVICES\" && \
    python3 -m vllm.entrypoints.openai.api_server \
        --model '$MODEL_PATH' \
        --port $PORT \
        --dtype auto \
        --trust-remote-code \
        --max-model-len $MAX_MODEL_LEN \
        --tensor-parallel-size $NUM_GPUS \
        --enforce-eager \
        --gpu-memory-utilization 0.92 \
        --max-num-seqs 32 \
        --max-num-batched-tokens 32768 \
        --enable-prefix-caching \
        $EXTRA_VLLM_ARGS
" &
VLLM_PID=$!
trap cleanup_vllm EXIT

echo ">>> Waiting for vLLM server (PID: $VLLM_PID)..."
for i in $(seq 1 120); do
    if curl -s http://localhost:${PORT}/health > /dev/null 2>&1; then
        echo ">>> vLLM server ready after $((i*5))s"
        break
    fi
    if ! kill -0 $VLLM_PID 2>/dev/null; then
        echo "ERROR: vLLM server died during startup"
        exit 1
    fi
    sleep 5
done

if ! curl -s http://localhost:${PORT}/health > /dev/null 2>&1; then
    echo "ERROR: vLLM server failed to start within 600s"
    exit 1
fi

LLM_SPEC="OPENAI::${MODEL_PATH}::dummy::http://localhost:${PORT}/v1"

# Build COT args
COT_ARGS=""
if [ -n "$COT_END_TOKENS" ]; then
    COT_ARGS="--cot-end-tokens '$COT_END_TOKENS'"
fi

# --- Step 2: Run benchmarks ---
run_benchmark() {
    local BENCH_NAME="$1"
    local PROMPT_FILE="$2"
    shift 2
    local EXTRA_ARGS="$*"

    local RESP_FILE="${RESULTS_DIR}/${BENCH_NAME}_responses.json"
    local STAT_FILE="${RESULTS_DIR}/${BENCH_NAME}_stat.json"

    if [ -f "$STAT_FILE" ]; then
        echo ">>> SKIP $BENCH_NAME (stat file exists)"
        return
    fi

    echo ""
    echo ">>> Running: $BENCH_NAME"
    echo "    $(date)"

    singularity exec "$CONTAINER" bash -lc "
        \$WITH_CONDA && source ${VENV_CSE}/bin/activate && \
        export PYTHONPATH='${PURPLE}:\${PYTHONPATH:-}' && \
        cd '$PURPLE' && \
        python3 -m CybersecurityBenchmarks.benchmark.run \
            --benchmark='$BENCH_NAME' \
            --prompt-path='$PROMPT_FILE' \
            --response-path='$RESP_FILE' \
            --stat-path='$STAT_FILE' \
            --llm-under-test='$LLM_SPEC' \
            --run-llm-in-parallel=8 \
            $COT_ARGS \
            $EXTRA_ARGS
    " 2>&1 || echo "WARNING: $BENCH_NAME failed"

    if [ -f "$STAT_FILE" ]; then
        echo ">>> $BENCH_NAME results:"
        python3 -c "import json; print(json.dumps(json.load(open('$STAT_FILE')), indent=2))" 2>/dev/null || cat "$STAT_FILE"
        echo ""
    fi
    echo "    Finished: $(date)"
}

# Autocomplete
run_benchmark "autocomplete" "$DATASETS/autocomplete/autocomplete.json"

# Instruct
run_benchmark "instruct" "$DATASETS/instruct/instruct.json"

# MITRE-FRR (no judge needed)
run_benchmark "mitre-frr" "$DATASETS/mitre_frr/mitre_frr.json"

# MITRE (needs judge + expansion LLM via OpenAI API)
if [ "$SKIP_MITRE" != "1" ]; then
    JUDGE_SPEC="OPENAI::gpt-4::${OPENAI_API_KEY}"
    run_benchmark "mitre" \
        "$DATASETS/mitre/mitre_benchmark_100_per_category_with_augmentation_clean.json" \
        "--judge-llm=$JUDGE_SPEC" \
        "--expansion-llm=$JUDGE_SPEC" \
        "--judge-response-path=${RESULTS_DIR}/mitre_judge_responses.json"
fi

echo ""
echo "=== All benchmarks complete for $MODEL_NAME ==="
echo "Results in: $RESULTS_DIR"
ls -la "$RESULTS_DIR"
