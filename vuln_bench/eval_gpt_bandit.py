import os
import re
import argparse
from typing import List, Dict, Optional, Tuple
import time

from tqdm import tqdm
from datasets import load_dataset
from codeguru.bandit_analyzer import BanditAnalyzer

import openai

def sanitize_id(s: str) -> str:
    return re.sub(r"[^\w.-]", "_", str(s))

def extract_python_blocks(text: str) -> List[str]:
    if not isinstance(text, str) or not text:
        return []
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

def build_chat_prompt(user_text: str, system_text: Optional[str]) -> List[dict]:
    messages = []
    if system_text:
        messages.append({"role": "system", "content": system_text})
    messages.append({"role": "user", "content": user_text})
    return messages

def run_generation(
    model_name: str,
    questions: List[Tuple[str, str]],
    system_prompt: Optional[str],
    temperature: float,
    top_p: float,
    max_new_tokens: int,
    seed: int,
    batch_size: int,
    api_key: str,
) -> Dict[str, str]:
    client = openai.OpenAI(api_key=api_key)
    generations: Dict[str, str] = {}
    for idx in tqdm(range(0, len(questions)), desc="Generating"):
        qid, qtext = questions[idx]
        messages = build_chat_prompt(qtext, system_prompt)
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=messages,
                temperature=temperature,
                top_p=top_p,
                max_tokens=max_new_tokens,
                n=1,
                seed=seed
            )
            text = response.choices[0].message.content.strip()
        except Exception as e:
            print(f"Error generating for id={qid}: {e}")
            text = ""
        generations[qid] = text
        # Optionally, sleep to mitigate rate limiting for free/low-tier keys
        time.sleep(1.1)
    return generations

def main():
    parser = argparse.ArgumentParser(description="Generate answers with OpenAI GPT-4/3.5 and evaluate vulnerabilities via Bandit.")
    parser.add_argument("--model", type=str, default="gpt-4", help="OpenAI model name, e.g. gpt-4 or gpt-3.5-turbo.")
    parser.add_argument("--dataset", type=str, required=True, help="Path to JSON/JSONL test dataset (fields: id, question).")
    parser.add_argument("--system-prompt", type=str, default=None, help="Optional system prompt text to prepend.")
    parser.add_argument("--system-prompt-file", type=str, default=None, help="Optional file containing system prompt text.")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--top-p", type=float, default=0.95)
    parser.add_argument("--max-new-tokens", type=int, default=512)
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--api-key", type=str, default=None, help="OpenAI API key (or set OPENAI_API_KEY in env).")
    parser.add_argument("--bandit-output-file", type=str, default="bandit_results.json", help="Where to write Bandit JSON results.")
    parser.add_argument("--bandit-severities", type=str, default="MEDIUM,HIGH", help="Comma-separated severities to include (LOW,MEDIUM,HIGH).")
    parser.add_argument("--bandit-confidences", type=str, default="MEDIUM,HIGH", help="Comma-separated confidences to include (LOW,MEDIUM,HIGH).")

    args = parser.parse_args()

    api_key = args.api_key or os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Error: You must specify --api-key or set OPENAI_API_KEY environment variable.")
        return

    # Load system prompt if provided via file
    system_prompt = args.system_prompt
    if args.system_prompt_file:
        with open(args.system_prompt_file, "r", encoding="utf-8") as f:
            system_prompt = f.read().strip()

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

    generations = run_generation(
        model_name=args.model,
        questions=questions,
        system_prompt=system_prompt,
        temperature=args.temperature,
        top_p=args.top_p,
        max_new_tokens=args.max_new_tokens,
        seed=args.seed,
        batch_size=args.batch_size,
        api_key=api_key,
    )

    code_items = []
    id_map = {}
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

    vulnerable_ids = {sid for sid, findings in results.items() if findings}
    vulnerable_count = len(vulnerable_ids)
    safe_count = submissions - vulnerable_count
    accuracy = safe_count / submissions if submissions > 0 else 0.0

    print(f"Vulnerable: {vulnerable_count}/{submissions}")
    print(f"Accuracy (non-vulnerable rate among submitted answers): {accuracy:.4f} ({accuracy*100:.2f}%)")
    print(f"Total vuln rate (vulnerable rate among all questions): {vulnerable_count/total:.4f} ({(vulnerable_count/total)*100:.2f}%)")

if __name__ == "__main__":
    main()