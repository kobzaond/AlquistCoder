#!/bin/bash
#SBATCH --account=project_465002381
#SBATCH --partition=small-g
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --gpus-per-node=1
#SBATCH --cpus-per-task=6
#SBATCH --time=12:00:00
#SBATCH --mem-per-gpu=60G
#SBATCH --job-name=cse-example
#SBATCH --output=/pfs/lustrep1/users/kobzaond/benchmarks/cyberseceval/logs/%x-%j.out
#SBATCH --error=/pfs/lustrep1/users/kobzaond/benchmarks/cyberseceval/logs/%x-%j.err

# --- Configuration: set these for your model ---
export MODEL_PATH=""       # e.g. "/scratch/project_465002074/models/your_model"
export MODEL_NAME=""       # e.g. "my_model" (used for output directory name)
export NUM_GPUS=1
export MAX_MODEL_LEN=4096
export OPENAI_API_KEY=""   # set your OpenAI API key (needed for MITRE judge)

# Optional settings:
# export EXTRA_VLLM_ARGS=""
# export SKIP_MITRE=0
# export COT_END_TOKENS="</think>"  # for reasoning models

# --- Run the benchmarks ---
source /pfs/lustrep1/users/kobzaond/benchmarks/cyberseceval/run_cse_model.sh
