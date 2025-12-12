import sys
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass
import os

from vllm import LLM, SamplingParams
from transformers import AutoTokenizer
from huggingface_hub import model_info

from config import (
    get_vllm_dtype,
    get_vllm_tp,
    get_vllm_gpu_mem_util,
    get_default_max_tokens,
    get_default_temperature,
    get_default_top_p,
    get_stop_tokens,
)

# --- Logger Setup ---
# We configure the logger to write directly to stdout with a timestamp.
logging.basicConfig(
    level=logging.INFO, # Change to logging.DEBUG for more verbose output
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("VLLMGenerator")

@dataclass
class VLLMConfig:
    model: str
    dtype: Optional[str] = None
    tensor_parallel_size: int = 1
    gpu_memory_utilization: float = 0.90

def _get_hf_token_from_env() -> Optional[str]:
    return os.getenv("HUGGINGFACE_HUB_TOKEN") or os.getenv("HF_TOKEN")

def _verify_model_access_or_die(model_id: str):
    token = _get_hf_token_from_env()
    try:
        info = model_info(model_id, token=token)
        if info.private:
            logger.warning(f"Model {model_id} is private; ensure your token has repo access.")
    except Exception as e:
        logger.error(f"Failed to access model {model_id}: {e}")
        raise RuntimeError(
            f"Cannot access model '{model_id}'. "
            "Check spelling, license acceptance, and your HUGGINGFACE_HUB_TOKEN. "
        ) from e

class VLLMGenerator:
    """
    Local in-process vLLM generator loading a Hugging Face model and generating
    via vLLM's LLM engine.
    """
    def __init__(self, model: str):
        logger.info(f"Initializing VLLMGenerator for model: {model}")
        self.cfg = VLLMConfig(
            model=model,
            dtype=get_vllm_dtype(),
            tensor_parallel_size=get_vllm_tp(),
            gpu_memory_utilization=get_vllm_gpu_mem_util(),
        )
        self._llm: Optional[LLM] = None
        self._tok: Optional[AutoTokenizer] = None
        self._stop: Optional[List[str]] = None

        _verify_model_access_or_die(model)

        if ("meta-llama/" in model.lower()) and not _get_hf_token_from_env():
            logger.warning(
                "Model appears gated (Meta-Llama). No HUGGINGFACE_HUB_TOKEN/HF_TOKEN found. "
                "Export a token or run `huggingface-cli login`."
            )

    def _lazy_init(self):
        if self._llm is None:
            logger.info("Loading vLLM engine (this may take a moment)...")
            try:
                self._llm = LLM(
                    model=self.cfg.model,
                    dtype=self.cfg.dtype,
                    tensor_parallel_size=self.cfg.tensor_parallel_size,
                    gpu_memory_utilization=self.cfg.gpu_memory_utilization,
                    trust_remote_code=True,
                )
                logger.info("vLLM engine loaded successfully.")
            except Exception as e:
                logger.critical(f"Failed to load vLLM engine: {e}")
                raise

        if self._tok is None:
            logger.info("Loading tokenizer...")
            hf_token = _get_hf_token_from_env()
            self._tok = AutoTokenizer.from_pretrained(
                self.cfg.model,
                trust_remote_code=True,
                token=hf_token,
            )
            
        if self._stop is None:
            stops = get_stop_tokens()
            if stops:
                self._stop = [s for s in stops.split(",") if s]
                logger.info(f"Stop tokens configured: {self._stop}")
            else:
                self._stop = None

    def _apply_chat_template(self, messages: List[Dict[str, str]]) -> str:
        self._lazy_init()
        try:
            return self._tok.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True,
                enable_thinking=True,
            )
        except Exception as e:
            logger.debug(f"Chat template application failed ({e}). Falling back to simple format.")
            # Fallback simple format if no chat template
            convo = ""
            for m in messages:
                role = m.get("role", "user")
                content = m.get("content", "")
                if role.lower() == "user":
                    convo += f"User: {content}\n"
                else:
                    convo += f"Assistant: {content}\n"
            convo += "Assistant:"
            return convo

    def generate(self, messages: List[Dict[str, str]]) -> str:
        self._lazy_init()
        prompt = self._apply_chat_template(messages)
        
        logger.debug("Starting single generation...")
        params = SamplingParams(
            max_tokens=get_default_max_tokens(),
            temperature=get_default_temperature(),
            top_p=get_default_top_p(),
            stop=self._stop,
        )
        
        outputs = self._llm.generate([prompt], params)
        if not outputs:
            logger.warning("vLLM returned no outputs.")
            return ""
            
        text = outputs[0].outputs[0].text if outputs[0].outputs else ""
        
        # Thinking logic extraction
        if "</think>" in text:
            logger.info("DeepSeek/Thinking model detected. Removing <think> tags.")
            parts = text.split("</think>")
            if len(parts) > 1:
                # Log the hidden thought for debugging purposes
                # logger.debug(f"Hidden thought: {parts[0]}")
                text = parts[1]
                
        return text.strip()

    def generate_batch(self, messages_list: List[List[Dict[str, str]]]) -> List[str]:
        if not messages_list:
            logger.warning("generate_batch called with empty message list.")
            return []
            
        self._lazy_init()
        logger.info(f"Starting batch generation for {len(messages_list)} items.")
        
        prompts = [self._apply_chat_template(msgs) for msgs in messages_list]
        params = SamplingParams(
            max_tokens=get_default_max_tokens(),
            temperature=get_default_temperature(),
            top_p=get_default_top_p(),
            stop=self._stop,
        )
        
        outputs = self._llm.generate(prompts, params)
        
        results: List[str] = []
        for i, out in enumerate(outputs):
            text = out.outputs[0].text if out.outputs else ""
            
            if "</think>" in text:
                logger.info(f"Item {i}: Extracted text after </think>.")
                text = text.split("</think>")[1]
            
            results.append(text.strip())

        # Safety: ensure alignment
        if len(results) != len(messages_list):
            logger.error(f"Mismatch in batch size: Input {len(messages_list)} vs Output {len(results)}")
            if len(results) < len(messages_list):
                results.extend([""] * (len(messages_list) - len(results)))
            else:
                results = results[:len(messages_list)]
                
        logger.info("Batch generation complete.")
        return results