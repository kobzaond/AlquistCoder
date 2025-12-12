import sys
from typing import Dict, Any, List

from datasets import Dataset
from data_utils import load_json_dataset, save_json_dataset, ensure_messages_list
from generators import ChatGenerator
from vllm_generator import VLLMGenerator
from config import get_candidate_model, get_vllm_base_url, get_batch_size

def _chunks(n_total: int, batch_size: int):
    for start in range(0, n_total, batch_size):
        end = min(n_total, start + batch_size)
        yield start, end

def main(
    dataset_path: str,
    out_path: str,
    engine: str = "openai",            # "openai" or "vllm"
    candidate_model: str = None,       # model id (HF id for vLLM; model name for openai-compatible)
    base_url: str = None,              # used only for engine="openai"
    enable_reasoning_for_gpt5: bool = False,
    max_samples: int = 0,
    batch_size: int = None,            # used for vLLM batching; defaults to APP_BATCH_SIZE
):
    ds = load_json_dataset(dataset_path)
    ds = ds.filter(lambda x: x['label']=='mal')
    n = ds.num_rows
    if max_samples and max_samples > 0:
        n = min(n, max_samples)
        ds = ds.select(range(n))
    else:
        n = ds.num_rows

    if candidate_model is None:
        candidate_model = get_candidate_model()
    if base_url is None:
        base_url = get_vllm_base_url()
    if batch_size is None or batch_size <= 0:
        batch_size = get_batch_size()
        if batch_size <= 0:
            batch_size = 1

    out_rows: List[Dict[str, Any]] = []

    if engine.lower() == "vllm":
        gen = VLLMGenerator(model=candidate_model)
        for start, end in _chunks(n, batch_size):
            batch_msgs_list: List[List[Dict[str, str]]] = []
            batch_samples = []
            for i in range(start, end):
                ex = ds[i]
                prompt_msgs = ensure_messages_list(ex.get("prompt"))
                batch_msgs_list.append(prompt_msgs)
                batch_samples.append(ex)
            try:
                batch_answers = gen.generate_batch(batch_msgs_list)
            except Exception as e:
                # On failure, fall back per-sample to avoid losing progress
                batch_answers = []
                for msgs in batch_msgs_list:
                    try:
                        batch_answers.append(gen.generate(msgs))
                    except Exception as e2:
                        batch_answers.append(f"[generation_error] {e2}")

            for j, ex in enumerate(batch_samples):
                out_ex = dict(ex)
                out_ex["prompt"] = batch_msgs_list[j]
                out_ex["engine"] = "vllm"
                out_ex["model_name"] = candidate_model
                out_ex["model_answer"] = batch_answers[j] if j < len(batch_answers) else ""
                out_rows.append(out_ex)

            sys.stderr.write(f"[info] vLLM generated {end}/{n}\n")

    else:
        # OpenAI-compatible (can point to vLLM OpenAI server via base_url); sequential per-sample
        enable_reasoning = enable_reasoning_for_gpt5 and ("gpt-5" in candidate_model.lower())
        gen = ChatGenerator(model=candidate_model, base_url=base_url, enable_reasoning=enable_reasoning)
        for i in range(n):
            ex = ds[i]
            prompt_msgs = ensure_messages_list(ex.get("prompt"))
            try:
                ans = gen.generate(messages=prompt_msgs)
            except Exception as e:
                ans = f"[generation_error] {e}"

            out_ex = dict(ex)
            out_ex["prompt"] = prompt_msgs
            out_ex["engine"] = "openai"
            out_ex["model_name"] = candidate_model
            out_ex["model_base_url"] = base_url or ""
            out_ex["model_answer"] = ans
            out_rows.append(out_ex)

            if (i + 1) % 25 == 0:
                sys.stderr.write(f"[info] OpenAI-compatible generated {i+1}/{n}\n")

    ds_out = Dataset.from_list(out_rows)
    save_json_dataset(ds_out, out_path, lines=True)
    sys.stderr.write(f"[done] Wrote generations to {out_path}\n")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python run_generate.py DATASET.jsonl OUT.jsonl [ENGINE openai|vllm] [CANDIDATE_MODEL] [BASE_URL or '' if none] [ENABLE_GPT5_REASONING:0/1] [MAX_SAMPLES] [BATCH_SIZE]")
        sys.exit(1)
    dataset_path = sys.argv[1]
    out_path = sys.argv[2]
    engine = sys.argv[3] if len(sys.argv) >= 4 else "openai"
    candidate_model = sys.argv[4] if len(sys.argv) >= 5 else None
    base_url = sys.argv[5] if len(sys.argv) >= 6 else None
    enable_reasoning = bool(int(sys.argv[6])) if len(sys.argv) >= 7 else False
    max_samples = int(sys.argv[7]) if len(sys.argv) >= 8 else 0
    batch_size = int(sys.argv[8]) if len(sys.argv) >= 9 else None
    print(sys.argv)

    main(dataset_path, out_path, engine, candidate_model, base_url, enable_reasoning, max_samples, batch_size)
