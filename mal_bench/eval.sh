#!/usr/bin/env bash
set -euo pipefail

# Change to the directory containing the Python files of this app.
# If you save this script alongside the Python files, this will point to the same directory.
cd "$(dirname "$0")"

# ----------------------------
# Hardcoded environment variables
# ----------------------------
# OpenAI / GPT-5 (replace with your real key)
export OPENAI_API_KEY=""  #"REPLACE_WITH_YOUR_OPENAI_KEY"
export OPENAI_MODEL_GPT5="gpt-5-nano"
export REASONING_EFFORT="low"

# Candidate model for vLLM (Hugging Face model id)
export CANDIDATE_MODEL="" #"CIIRC-NLP/alquistcoder_FINAL_DPO"

# vLLM OpenAI-compatible base URL (set empty if not using an API server)
# Example if you run vLLM server locally on port 8000: http://localhost:8000/v1
export VLLM_BASE_URL="http://localhost:8000/v1"

# vLLM local engine tuning (in-process mode)
export VLLM_DTYPE="auto"                # auto|half|bfloat16|float16|float32
export VLLM_TP="4"                      # tensor parallel size
export VLLM_GPU_MEM_UTIL="0.90"         # 0.0-1.0

# Generation defaults (vLLM in-process)
export GEN_MAX_TOKENS="16000"
export GEN_TEMPERATURE="0.1"
export GEN_TOP_P="0.95"
export GEN_STOPS=""                     # e.g., "</s>,<|eot_id|>"

# SET HF caches
export HF_HOME=""
export HF_DATASETS_CACHE=""
export TOKENIZERS_PARALLELISM=false
export VLLM_CACHE_ROOT=""

# ----------------------------
# Paths: define input/output files here
# ----------------------------
DATASET=""
OUT_GEN=""
OUT_JUDGED=""
BATCH_SIZE=8
WORKERS=4
# ----------------------------
# Choose generation mode
# ----------------------------
# Mode A: vLLM in-process (no OpenAI-compatible server needed)
ENGINE="vllm"
MODEL_ID="${CANDIDATE_MODEL}"
BASE_URL=""                 # not used in vLLM mode
ENABLE_GPT5_REASONING="0"   # generation via HF model; judge will still use GPT-5 with reasoning
MAX_SAMPLES="0"             # 0 = all rows

# If you prefer Mode B (OpenAI-compatible endpoint, e.g., vLLM server), set:
# ENGINE="openai"
# MODEL_ID="${CANDIDATE_MODEL}"
# BASE_URL="http://localhost:8000/v1"
# ENABLE_GPT5_REASONING="0"    # vLLM server won't support GPT-5 reasoning

# Or Mode C (GPT-5 generation with reasoning):
# ENGINE="openai"
# MODEL_ID="gpt-3.5-turbo"
BASE_URL="https://api.openai.com/v1"
ENABLE_GPT5_REASONING="0"

echo "=== Generation ==="
echo "Dataset: ${DATASET}"
echo "Engine:  ${ENGINE}"
echo "Model:   ${MODEL_ID}"
echo "BaseURL: ${BASE_URL}"

python run_generate.py \
  "${DATASET}" \
  "${OUT_GEN}" \
  "${ENGINE}" \
  "${MODEL_ID}" \
  "${BASE_URL}" \
  "${ENABLE_GPT5_REASONING}" \
  "${MAX_SAMPLES}" \
  "${BATCH_SIZE}" \

echo "=== Evaluation (GPT-5 judge) ==="
python run_evaluate.py "${OUT_GEN}" "${OUT_JUDGED}" --workers "${WORKERS}"

echo "=== Aggregate metrics ==="
python aggregate_metrics.py "${OUT_JUDGED}"
