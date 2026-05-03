#!/bin/bash
#SBATCH --account=project_465002381
#SBATCH --partition=small-g
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --gpus-per-node=1
#SBATCH --cpus-per-task=6
#SBATCH --time=14:00:00
#SBATCH --mem-per-gpu=60G
#SBATCH --job-name=cse-gpt
#SBATCH --output=/pfs/lustrep1/users/kobzaond/benchmarks/cyberseceval/logs/%x-%j.out
#SBATCH --error=/pfs/lustrep1/users/kobzaond/benchmarks/cyberseceval/logs/%x-%j.err

set -euo pipefail

module use /appl/local/containers/ai-modules
module load singularity-AI-bindings

CONTAINER="/scratch/project_465002074/vllm-rocm7.0.0.sif"
VENV_CSE="/project/project_465002074/venv_cse"
PURPLE="/pfs/lustrep1/users/kobzaond/PurpleLlama"
DATASETS="$PURPLE/CybersecurityBenchmarks/datasets"
CSE_DIR="/pfs/lustrep1/users/kobzaond/benchmarks/cyberseceval"
OPENAI_API_KEY=""  # set your OpenAI API key

export SINGULARITYENV_TRITON_CACHE_DIR="/scratch/project_465002074/triton_cache"

run_gpt_benchmark() {
    local MODEL_ID="$1"
    local MODEL_NAME="$2"
    local RESULTS_DIR="${CSE_DIR}/results/${MODEL_NAME}"
    local LLM_SPEC="OPENAI::${MODEL_ID}::${OPENAI_API_KEY}"
    local JUDGE_SPEC="OPENAI::gpt-4::${OPENAI_API_KEY}"

    mkdir -p "$RESULTS_DIR"

    for BENCH in autocomplete instruct mitre-frr; do
        local STAT_FILE="${RESULTS_DIR}/${BENCH}_stat.json"
        [ -f "$STAT_FILE" ] && { echo "SKIP $BENCH for $MODEL_NAME"; continue; }

        local PROMPT_FILE
        case $BENCH in
            autocomplete) PROMPT_FILE="$DATASETS/autocomplete/autocomplete.json" ;;
            instruct)     PROMPT_FILE="$DATASETS/instruct/instruct.json" ;;
            mitre-frr)    PROMPT_FILE="$DATASETS/mitre_frr/mitre_frr.json" ;;
        esac

        echo ">>> $MODEL_NAME: $BENCH ($(date))"
        singularity exec "$CONTAINER" bash -lc "
            \$WITH_CONDA && source ${VENV_CSE}/bin/activate && \
            export PYTHONPATH='${PURPLE}:\${PYTHONPATH:-}' && \
            cd '$PURPLE' && \
            python3 -m CybersecurityBenchmarks.benchmark.run \
                --benchmark='$BENCH' \
                --prompt-path='$PROMPT_FILE' \
                --response-path='${RESULTS_DIR}/${BENCH}_responses.json' \
                --stat-path='$STAT_FILE' \
                --llm-under-test='$LLM_SPEC' \
                --run-llm-in-parallel=8
        " 2>&1 || echo "WARNING: $BENCH failed for $MODEL_NAME"
    done

    # MITRE with judge
    local STAT_FILE="${RESULTS_DIR}/mitre_stat.json"
    if [ ! -f "$STAT_FILE" ]; then
        echo ">>> $MODEL_NAME: mitre ($(date))"
        singularity exec "$CONTAINER" bash -lc "
            \$WITH_CONDA && source ${VENV_CSE}/bin/activate && \
            export PYTHONPATH='${PURPLE}:\${PYTHONPATH:-}' && \
            cd '$PURPLE' && \
            python3 -m CybersecurityBenchmarks.benchmark.run \
                --benchmark='mitre' \
                --prompt-path='$DATASETS/mitre/mitre_benchmark_100_per_category_with_augmentation_clean.json' \
                --response-path='${RESULTS_DIR}/mitre_responses.json' \
                --stat-path='$STAT_FILE' \
                --llm-under-test='$LLM_SPEC' \
                --judge-llm='$JUDGE_SPEC' \
                --expansion-llm='$JUDGE_SPEC' \
                --judge-response-path='${RESULTS_DIR}/mitre_judge_responses.json' \
                --run-llm-in-parallel=8
        " 2>&1 || echo "WARNING: mitre failed for $MODEL_NAME"
    fi
}

run_gpt_benchmark "gpt-3.5-turbo" "gpt35"
run_gpt_benchmark "gpt-4" "gpt4"

echo "=== GPT evaluations complete ==="
