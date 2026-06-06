"""VulnBench: generate code completions and optionally run Bandit analysis.

Two-step workflow for models requiring separate generation (e.g., reasoning models
with large token budgets):
  1. Generate completions (this script)
  2. Run Bandit analysis (eval_vuln_with_bandit_standalone.py)

Or single-step: pass --bandit-output-file to do both in one shot.

Usage:
    python generate_and_save.py \
        --model Qwen/Qwen3-8B \
        --dataset dpo_test_questions.jsonl \
        --output-file generations.jsonl \
        --temperature 0.1

    # For reasoning models:
    python generate_and_save.py \
        --model Qwen/Qwen3-8B \
        --dataset dpo_test_questions.jsonl \
        --output-file generations.jsonl \
        --enable-thinking \
        --max-new-tokens 16000 \
        --max-model-len 40960 \
        --temperature 0.1
"""
import os
import re
import json
import argparse
from typing import List, Dict, Optional, Tuple

os.environ.setdefault("VLLM_ATTENTION_BACKEND", "FLASH_ATTN")
os.environ.setdefault("CUDA_COREDUMP_ENABLE", "0")
os.environ.setdefault("VLLM_USE_V1", "1")

from tqdm import tqdm
from datasets import load_dataset
from vllm import LLM, SamplingParams

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "codeguru-analyzer"))
from codeguru.bandit_analyzer import BanditAnalyzer


def strip_thinking(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL).strip()


def extract_python_blocks(text: str) -> List[str]:
    if not isinstance(text, str) or not text:
        return []
    text = strip_thinking(text)
    pattern = re.compile(r"```(?:python|py)\s*\n(.*?)```", re.IGNORECASE | re.DOTALL)
    blocks = pattern.findall(text)
    if not blocks:
        pattern_plain = re.compile(r"```\s*\n(.*?)```", re.DOTALL)
        blocks = pattern_plain.findall(text)
    return [b.strip() for b in blocks if b and b.strip()]


def join_blocks(blocks: List[str]) -> str:
    if not blocks:
        return ""
    if len(blocks) == 1:
        return blocks[0]
    return "\n\n".join(blocks)


def build_chat_prompt(tokenizer, user_text: str, system_text: Optional[str], enable_thinking: bool = False) -> str:
    messages = []
    if system_text:
        messages.append({"role": "system", "content": system_text})
    messages.append({"role": "user", "content": user_text})
    try:
        return tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True, enable_thinking=enable_thinking,
        )
    except TypeError:
        return tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True,
        )


def main():
    parser = argparse.ArgumentParser(description="VulnBench: generate code completions")
    parser.add_argument("--model", type=str, required=True, help="HuggingFace model name or path")
    parser.add_argument("--dataset", type=str, required=True, help="JSONL dataset with 'id' and 'question' fields")
    parser.add_argument("--system-prompt", type=str, default=None)
    parser.add_argument("--system-prompt-file", type=str, default=None,
                        help="Path to file containing system prompt (overrides --system-prompt)")
    parser.add_argument("--output-file", type=str, required=True, help="JSONL file to save raw generations")
    parser.add_argument("--bandit-output-file", type=str, default=None, help="Optional: run Bandit and save results")
    parser.add_argument("--temperature", type=float, default=0.1)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--top-k", type=int, default=50)
    parser.add_argument("--max-new-tokens", type=int, default=800)
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--max-model-len", type=int, default=4096)
    parser.add_argument("--batch-size", type=int, default=20)
    parser.add_argument("--bandit-severities", type=str, default="MEDIUM,HIGH")
    parser.add_argument("--bandit-confidences", type=str, default="MEDIUM,HIGH")
    parser.add_argument("--enable-thinking", action="store_true", help="Enable thinking/reasoning tokens (for Qwen3)")
    parser.add_argument("--tensor-parallel-size", type=int, default=1)
    args = parser.parse_args()

    if args.system_prompt_file:
        with open(args.system_prompt_file) as f:
            args.system_prompt = f.read().strip()

    ds = load_dataset("json", data_files=args.dataset, split="train")
    questions: List[Tuple[str, str]] = []
    for i in range(ds.num_rows):
        row = ds[i]
        qid = str(row.get("id"))
        q = row.get("question")
        if not qid or not isinstance(q, str) or not q.strip():
            continue
        questions.append((qid, q.strip()))

    print(f"Loaded {len(questions)} questions")

    llm = LLM(
        model=args.model, dtype="auto", trust_remote_code=True,
        max_model_len=args.max_model_len, tensor_parallel_size=args.tensor_parallel_size,
        enforce_eager=True, gpu_memory_utilization=0.95,
        max_num_seqs=max(args.batch_size, 32), max_num_batched_tokens=32768,
        enable_prefix_caching=False,
    )
    tokenizer = llm.get_tokenizer()

    sampling_params = SamplingParams(
        temperature=args.temperature, top_p=args.top_p, top_k=args.top_k,
        max_tokens=args.max_new_tokens, seed=args.seed,
    )

    prompts, ids = [], []
    for qid, qtext in questions:
        prompts.append(build_chat_prompt(tokenizer, qtext, args.system_prompt, enable_thinking=args.enable_thinking))
        ids.append(qid)

    generations: Dict[str, str] = {}
    for start in tqdm(range(0, len(prompts), args.batch_size), desc="Generating"):
        end = min(start + args.batch_size, len(prompts))
        outs = llm.generate(prompts[start:end], sampling_params)
        for qid, out in zip(ids[start:end], outs):
            text = (out.outputs[0].text if out.outputs else "").strip()
            generations[qid] = text

    question_map = {qid: qtext for qid, qtext in questions}
    with open(args.output_file, "w", encoding="utf-8") as f:
        for qid in ids:
            answer = generations.get(qid, "")
            blocks = extract_python_blocks(answer)
            code = join_blocks(blocks) if blocks else ""
            record = {
                "id": qid,
                "question": question_map[qid],
                "raw_answer": answer,
                "extracted_code": code,
                "has_code": bool(blocks),
                "num_code_blocks": len(blocks),
            }
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"Saved {len(generations)} generations to {args.output_file}")

    no_code = [qid for qid in ids if not extract_python_blocks(generations.get(qid, ""))]
    print(f"Questions with no extracted code blocks (potential refusals): {len(no_code)}/{len(ids)}")

    if args.bandit_output_file:
        code_items = []
        for qid, answer in generations.items():
            blocks = extract_python_blocks(answer)
            code = join_blocks(blocks) if blocks else answer
            if not code.strip():
                code = answer
            sid = re.sub(r"[^\w.-]", "_", str(qid))
            code_items.append({"id": sid, "code": code})

        severity_levels = [s.strip().upper() for s in args.bandit_severities.split(",") if s.strip()]
        confidence_levels = [c.strip().upper() for c in args.bandit_confidences.split(",") if c.strip()]

        results = BanditAnalyzer.analyze_code(
            code_data=code_items, output_file=args.bandit_output_file,
            confidence_levels=confidence_levels, severity_levels=severity_levels,
        )
        if results:
            vulnerable_ids = {sid for sid, findings in results.items() if findings}
            print(f"Vulnerable: {len(vulnerable_ids)}/{len(code_items)}")


if __name__ == "__main__":
    main()
