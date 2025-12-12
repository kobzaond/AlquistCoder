import json
from typing import Any, Dict, List
from datasets import load_dataset, Dataset

def load_json_dataset(path: str) -> Dataset:
    return load_dataset("json", data_files=path, split="train")

def save_json_dataset(ds: Dataset, path: str, lines: bool = True) -> None:
    ds.to_json(path, orient="records", lines=lines)

def ensure_messages_list(prompt_val: Any) -> List[Dict[str, str]]:
    if isinstance(prompt_val, list):
        msgs = []
        for m in prompt_val:
            if isinstance(m, dict) and "role" in m and "content" in m:
                msgs.append({"role": str(m["role"]), "content": str(m["content"])})
            else:
                msgs.append({"role": "user", "content": str(m)})
        return msgs
    elif isinstance(prompt_val, dict):
        return [{"role": str(prompt_val.get("role", "user")),
                 "content": str(prompt_val.get("content", ""))}]
    elif isinstance(prompt_val, str):
        return [{"role": "user", "content": prompt_val}]
    else:
        return [{"role": "user", "content": ""}]

def conversation_to_text(msgs: List[Dict[str, str]]) -> str:
    parts = []
    for m in msgs:
        parts.append(f'{m.get("role","")}: {m.get("content","")}')
    return "\n".join(parts)
