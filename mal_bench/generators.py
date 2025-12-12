import time
from typing import List, Dict, Optional

from openai import OpenAI
from config import get_openai_api_key, get_vllm_base_url, get_reasoning_effort

class ChatGenerator:
    """
    OpenAI-compatible chat generator.
    - If base_url is provided, can connect to a vLLM server exposing OpenAI-compatible API.
    - Can enable reasoning for GPT-5 (server may ignore if unsupported).
    """
    def __init__(self, model: str, base_url: Optional[str] = None, enable_reasoning: bool = False):
        self.model = model
        self.enable_reasoning = enable_reasoning
        api_key = get_openai_api_key()
        if base_url:
            self.client = OpenAI(base_url=base_url, api_key=api_key)
        else:
            self.client = OpenAI(api_key=api_key)
        self.reasoning_effort = get_reasoning_effort()

    def generate(self, messages: List[Dict[str, str]], max_retries: int = 3) -> str:
        last_err = None
        for attempt in range(max_retries):
            try:
                kwargs = {}
                if self.enable_reasoning:
                    kwargs["reasoning"] = {"effort": self.reasoning_effort}
                resp = self.client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    **kwargs,
                )
                return (resp.choices[0].message.content or "").strip()
            except Exception as e:
                last_err = e
                time.sleep(2 ** attempt)
        raise RuntimeError(f"Generation failed after retries: {last_err}")
