# eval_vuln_with_bandit.py
import os
import re
import argparse
from typing import List, Dict, Optional, Tuple

# vLLM runtime env (tweak if needed for your stack)
os.environ.setdefault("VLLM_ATTENTION_BACKEND", "FLASH_ATTN")
os.environ.setdefault("CUDA_COREDUMP_ENABLE", "0")
os.environ.setdefault("VLLM_USE_V1", "1")

from tqdm import tqdm
from datasets import load_dataset
from vllm import LLM, SamplingParams
from codeguru.bandit_analyzer import BanditAnalyzer


def sanitize_id(s: str) -> str:
    # Keep IDs filesystem-safe for temp files created by BanditAnalyzer
    return re.sub(r"[^\w.-]", "_", str(s))


def extract_python_blocks(text: str) -> List[str]:
    if not isinstance(text, str) or not text:
        return []
    # capture fenced Python blocks
    pattern = re.compile(r"```(?:python|py)\s*\n(.*?)```", re.IGNORECASE | re.DOTALL)
    blocks = pattern.findall(text)
    return [b.strip() for b in blocks if b and b.strip()]


def join_blocks(blocks: List[str]) -> str:
    if not blocks:
        return ""
    if len(blocks) == 1:
        return blocks[0]
    sep = "\n\n# ===== cell separator =====\n\n"
    return sep.join(blocks)


def build_chat_prompt(tokenizer, user_text: str, system_text: Optional[str]) -> str:
    messages = []
    if system_text:
        messages.append({"role": "system", "content": system_text})
    messages.append({"role": "user", "content": user_text})

    try:
        return tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
            enable_thinking=True,
        )
    except TypeError:
        return tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=True,
        )


def run_generation(
    model_path: str,
    questions: List[Tuple[str, str]],
    system_prompt: Optional[str],
    temperature: float,
    top_p: float,
    top_k: int,
    max_new_tokens: int,
    seed: int,
    max_model_len: int,
    batch_size: int,
) -> Dict[str, str]:
    llm = LLM(
        model=model_path,
        dtype="auto",
        trust_remote_code=True,
        max_model_len=max_model_len,
        tensor_parallel_size=1,
        # enforce_eager=True,
        gpu_memory_utilization=0.95,
        max_num_seqs=max(batch_size, 8),
        max_num_batched_tokens=16768,
        enable_prefix_caching=False,
    )
    tokenizer = llm.get_tokenizer()

    prompts: List[str] = []
    ids: List[str] = []
    for qid, qtext in questions:
        prompt_text = build_chat_prompt(tokenizer, qtext, system_prompt)
        prompts.append(prompt_text)
        ids.append(qid)

    sampling_params = SamplingParams(
        temperature=temperature,
        top_p=top_p,
        top_k=top_k,
        max_tokens=max_new_tokens,
        seed=seed,
    )

    generations: Dict[str, str] = {}
    for start in tqdm(range(0, len(prompts), batch_size), desc="Generating"):
        end = min(start + batch_size, len(prompts))
        batch_prompts = prompts[start:end]
        batch_ids = ids[start:end]

        outs = llm.generate(batch_prompts, sampling_params)
        for qid, out in zip(batch_ids, outs):
            text = (out.outputs[0].text if out.outputs else "").strip()
            generations[qid] = text

    return generations


def main():
    parser = argparse.ArgumentParser(description="Generate answers with vLLM and evaluate vulnerabilities via Bandit.")
    parser.add_argument("--model", type=str, required=True, help="Path to vLLM-loadable model checkpoint.")
    parser.add_argument("--dataset", type=str, required=True, help="Path to JSON/JSONL test dataset (fields: id, question).")
    parser.add_argument("--system-prompt", type=str, default=None, help="Optional system prompt text to prepend.")
    parser.add_argument("--system-prompt-file", type=str, default=None, help="Optional file containing system prompt text.")

    # vLLM gen params
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--top-k", type=int, default=50)
    parser.add_argument("--max-new-tokens", type=int, default=512)
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--max-model-len", type=int, default=4096)
    parser.add_argument("--batch-size", type=int, default=20)

    # Bandit params
    parser.add_argument("--bandit-output-file", type=str, default="bandit_results.json", help="Where to write Bandit JSON results.")
    parser.add_argument("--bandit-severities", type=str, default="MEDIUM,HIGH", help="Comma-separated severities to include (LOW,MEDIUM,HIGH).")
    parser.add_argument("--bandit-confidences", type=str, default="MEDIUM,HIGH", help="Comma-separated confidences to include (LOW,MEDIUM,HIGH).")

    args = parser.parse_args()

    # Load system prompt if provided via file
    system_prompt = args.system_prompt
    if args.system_prompt_file:
        with open(args.system_prompt_file, "r", encoding="utf-8") as f:
            system_prompt = f.read().strip()

    # Load dataset
    ds = load_dataset("json", data_files=args.dataset, split="train")
    questions: List[Tuple[str, str]] = []
    for i in range(ds.num_rows):
        row = ds[i]
        qid = str(row.get("id"))
        q = row.get("question")
        if not qid or not isinstance(q, str) or not q.strip():
            continue
        questions.append((qid, q.strip()))
    if not questions:
        print("No valid questions found in dataset.")
        return

    # Generate answers
    generations = run_generation(
        model_path=args.model,
        questions=questions,
        system_prompt=system_prompt,
        temperature=args.temperature,
        top_p=args.top_p,
        top_k=args.top_k,
        max_new_tokens=args.max_new_tokens,
        seed=args.seed,
        max_model_len=args.max_model_len,
        batch_size=args.batch_size,
    )

    # Prepare code submissions (prefer fenced Python code; fallback to full answer)
    code_items = []
    id_map = {}  # sanitized_id -> original qid
    for qid, answer in generations.items():
        blocks = extract_python_blocks(answer)
        if not blocks:
            code = answer
        else:
            code = join_blocks(blocks)
            if not code.strip():
                code = answer
        sid = sanitize_id(qid)
        code_items.append({"id": sid, "code": code})
        print({"id": sid, "code": code})
        id_map[sid] = qid

    total = len(questions)
    submissions = len(code_items)
    print(f"Total questions: {total}")
    print(f"Prepared code submissions for Bandit: {submissions}")

    if submissions == 0:
        print("No code found in generations. Vulnerability evaluation is skipped.")
        print("Vulnerable: 0/0; Accuracy: N/A")
        return

    # Parse Bandit filters
    severity_levels = [s.strip().upper() for s in args.bandit_severities.split(",") if s.strip()]
    confidence_levels = [c.strip().upper() for c in args.bandit_confidences.split(",") if c.strip()]

    print("Running Bandit analysis...")
    results = BanditAnalyzer.analyze_code(
        code_data=code_items,
        output_file=args.bandit_output_file,
        confidence_levels=confidence_levels if confidence_levels else None,
        severity_levels=severity_levels if severity_levels else None,
    )

    if results is None:
        print("Bandit analysis failed. Cannot compute vulnerability stats.")
        return

    # results: dict of {sanitized_id: [findings]} only for items WITH findings (after filtering)
    vulnerable_ids = {sid for sid, findings in results.items() if findings}
    vulnerable_count = len(vulnerable_ids)
    safe_count = submissions - vulnerable_count
    accuracy = safe_count / submissions if submissions > 0 else 0.0

    print(f"Vulnerable: {vulnerable_count}/{submissions}")
    print(f"Accuracy (non-vulnerable rate among submitted answers): {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Total vuln rate (vulnerable rate among all questions): {vulnerable_count/total:.4f} ({(vulnerable_count/total)*100:.2f}%)")


if __name__ == "__main__":
    main()