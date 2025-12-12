import os

def get_openai_api_key() -> str:
    key = os.getenv("OPENAI_API_KEY", "")
    if not key:
        raise RuntimeError("OPENAI_API_KEY is not set.")
    return key

def get_gpt5_model() -> str:
    return os.getenv("OPENAI_MODEL_GPT5", "gpt-5")

def get_candidate_model() -> str:
    # Hugging Face model id for local vLLM OR a remote model name for OpenAI-compatible endpoint
    return os.getenv("CANDIDATE_MODEL", "meta-llama/Llama-3-8B-Instruct")

def get_vllm_base_url() -> str:
    # If set, generator will use OpenAI-compatible server (e.g., http://host:8000/v1)
    return os.getenv("VLLM_BASE_URL", "").strip()

def get_batch_size() -> int:
    try:
        return int(os.getenv("APP_BATCH_SIZE", "1"))
    except Exception:
        return 1

def get_reasoning_effort() -> str:
    return os.getenv("REASONING_EFFORT", "medium")

# vLLM local engine configuration
def get_vllm_dtype() -> str:
    # "auto", "half", "bfloat16", "float16", "float32"
    return os.getenv("VLLM_DTYPE", "auto")

def get_vllm_tp() -> int:
    # Tensor parallel size
    try:
        return int(os.getenv("VLLM_TP", "1"))
    except Exception:
        return 1

def get_vllm_gpu_mem_util() -> float:
    try:
        return float(os.getenv("VLLM_GPU_MEM_UTIL", "0.90"))
    except Exception:
        return 0.90

def get_default_max_tokens() -> int:
    try:
        return int(os.getenv("GEN_MAX_TOKENS", "16000"))
    except Exception:
        return 16000

def get_default_temperature() -> float:
    # Use model default if you prefer; here we keep a sensible default
    try:
        return float(os.getenv("GEN_TEMPERATURE", "0.7"))
    except Exception:
        return 0.7

def get_default_top_p() -> float:
    try:
        return float(os.getenv("GEN_TOP_P", "0.95"))
    except Exception:
        return 0.95

def get_stop_tokens() -> str:
    # Comma-separated custom stops (optional)
    return os.getenv("GEN_STOPS", "").strip()
