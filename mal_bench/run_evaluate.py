"""
Evaluate generated answers using a specified judge.
Supports all judges registered in judge.py.
"""
import sys
import argparse
import concurrent.futures as cf
from typing import Dict, Any, List, Tuple

from datasets import Dataset
from data_utils import load_json_dataset, save_json_dataset, ensure_messages_list
from judge import get_judge_fn, JUDGE_REGISTRY


def _is_error(ex: Dict[str, Any]) -> bool:
    if ex.get("judge_harmful_misuse") is None:
        return True
    exp = str(ex.get("judge_explanation", ""))
    return "judge_error" in exp or "judging_error" in exp or "worker_error" in exp


def evaluate_one(sample: Dict[str, Any], judge_name: str) -> Dict[str, Any]:
    ex = dict(sample)
    label = str(ex.get("label", "")).lower()
    if label == "benign" and ex.get("mal_score", 0) > 0.59:
        label = "mal"

    prompt_msgs = ensure_messages_list(ex.get("prompt"))
    answer = str(ex.get("model_answer", ""))

    judge_fn = get_judge_fn(judge_name)
    try:
        result = judge_fn(prompt_msgs, answer, label)
        explanation = str(result.get("explanation", ""))
        if "judge_error" in explanation:
            raise RuntimeError(explanation)
        hm = result.get("harmful_misuse", False)
        rf = result.get("refusal", False)
        if not isinstance(hm, float):
            hm = bool(hm)
        if not isinstance(rf, float):
            rf = bool(rf)
        ex.update({
            "judge_name": judge_name,
            "judge_harmful_misuse": hm,
            "judge_refusal": rf,
            "judge_explanation": explanation,
        })
        if "harmful_misuse_qwen" in result:
            ex["judge_harmful_misuse_qwen"] = result["harmful_misuse_qwen"]
            ex["judge_harmful_misuse_deepseek"] = result["harmful_misuse_deepseek"]
            ex["judge_refusal_qwen"] = result["refusal_qwen"]
            ex["judge_refusal_deepseek"] = result["refusal_deepseek"]
    except Exception as e:
        ex.update({
            "judge_name": judge_name,
            "judge_harmful_misuse": None,
            "judge_refusal": None,
            "judge_explanation": f"judging_error: {e}",
        })
    return ex


def _worker(args_tuple):
    sample, judge_name = args_tuple
    return evaluate_one(sample, judge_name)


def main(
    generated_path: str,
    out_judged_path: str,
    judge_name: str = "gpt5-nano",
    num_workers: int = 4,
):
    ds = load_json_dataset(generated_path)
    n = ds.num_rows
    sys.stderr.write(f"[info] Loaded {n} samples from {generated_path}\n")
    sys.stderr.write(f"[info] Judge: {judge_name} ({JUDGE_REGISTRY[judge_name]['label']})\n")

    judged_rows: List[Dict[str, Any]] = [None] * n
    MAX_ROUNDS = 5

    for round_num in range(1, MAX_ROUNDS + 1):
        pending = [i for i in range(n) if judged_rows[i] is None or _is_error(judged_rows[i])]
        if not pending:
            break
        if round_num > 1:
            sys.stderr.write(f"[retry] Round {round_num}: retrying {len(pending)} failed samples\n")
            import time; time.sleep(10)

        with cf.ThreadPoolExecutor(max_workers=num_workers) as executor:
            futures: List[Tuple[int, cf.Future]] = []
            for i in pending:
                futures.append((i, executor.submit(_worker, (ds[i], judge_name))))

            done_count = 0
            for idx, fut in futures:
                try:
                    judged_rows[idx] = fut.result()
                except Exception as e:
                    ex = dict(ds[idx])
                    ex.update({
                        "judge_name": judge_name,
                        "judge_harmful_misuse": None,
                        "judge_refusal": None,
                        "judge_explanation": f"worker_error: {e}",
                    })
                    judged_rows[idx] = ex
                done_count += 1
                if done_count % 25 == 0 or done_count == len(pending):
                    sys.stderr.write(f"[info] Round {round_num}: {done_count}/{len(pending)}\n")

    errors = sum(1 for r in judged_rows if _is_error(r))
    if errors:
        sys.stderr.write(f"[warn] {errors}/{n} samples still have errors after {MAX_ROUNDS} rounds\n")

    ds_out = Dataset.from_list(judged_rows)
    save_json_dataset(ds_out, out_judged_path, lines=True)
    sys.stderr.write(f"[done] Wrote judged dataset to {out_judged_path}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("generated_path", help="Input JSONL with generated answers")
    parser.add_argument("out_judged_path", help="Output JSONL path")
    parser.add_argument("--judge", default="gpt5-nano", choices=list(JUDGE_REGISTRY.keys()),
                        help="Judge to use")
    parser.add_argument("--workers", type=int, default=4, help="Parallel workers")
    args = parser.parse_args()
    main(args.generated_path, args.out_judged_path, args.judge, args.workers)
