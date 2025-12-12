import sys
import argparse
import concurrent.futures as cf
from typing import Dict, Any, List, Tuple

from datasets import Dataset
from data_utils import load_json_dataset, save_json_dataset, ensure_messages_list
from judge_gpt5 import judge_sample


def evaluate_one(sample: Dict[str, Any]) -> Dict[str, Any]:
    """
    Judge a single sample and return the updated row.
    """
    ex = dict(sample)  # shallow copy to avoid mutating input
    label = str(ex.get("label", "")).lower()
    if label == "benign" and ex.get("mal_score", 0) > 0.59:
        label = "mal"

    prompt_msgs = ensure_messages_list(ex.get("prompt"))
    answer = str(ex.get("model_answer", ""))

    try:
        judge = judge_sample(prompt_msgs, answer, label)
        ex.update(
            {
                "judge_harmful_misuse": bool(judge.get("harmful_misuse", False)),
                "judge_refusal": bool(judge.get("refusal", False)),
                "judge_explanation": str(judge.get("explanation", "")),
            }
        )
    except Exception as e:
        # Fail-safe: include error info but keep pipeline moving
        ex.update(
            {
                "judge_harmful_misuse": None,
                "judge_refusal": None,
                "judge_explanation": f"judging_error: {e}",
            }
        )

    return ex


def main(
    generated_path: str,
    out_judged_path: str,
    num_workers: int = 4,
):
    ds = load_json_dataset(generated_path)
    n = ds.num_rows
    sys.stderr.write(f"[info] Loaded {n} samples from {generated_path}\n")

    # Parallel evaluation
    # Use ProcessPool for CPU-bound or side-effect isolation; switch to ThreadPool if judge_sample is mostly I/O-bound.
    judged_rows: List[Dict[str, Any]] = [None] * n  # type: ignore

    # Submit tasks incrementally to avoid holding the entire dataset in memory
    with cf.ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures: List[Tuple[int, cf.Future]] = []
        for i in range(n):
            futures.append((i, executor.submit(evaluate_one, ds[i])))

        for idx, fut in futures:
            try:
                judged_rows[idx] = fut.result()
            except Exception as e:
                print(e)
                # If a worker crashes for this item, write a minimal fallback
                ex = dict(ds[idx])
                ex.update(
                    {
                        "judge_harmful_misuse": None,
                        "judge_refusal": None,
                        "judge_explanation": f"worker_error: {e}",
                    }
                )
                judged_rows[idx] = ex

            if (idx + 1) % 25 == 0 or (idx + 1) == n:
                sys.stderr.write(f"[info] Judged {idx+1}/{n}\n")

    # Build and save output dataset
    ds_out = Dataset.from_list(judged_rows)  # type: ignore
    save_json_dataset(ds_out, out_judged_path, lines=True)
    sys.stderr.write(f"[done] Wrote judged dataset to {out_judged_path}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate generated answers in parallel using judge_gpt5.")
    parser.add_argument("generated_path", type=str, help="Input JSONL file with generated samples.")
    parser.add_argument("out_judged_path", type=str, help="Output JSONL path for judged results.")
    parser.add_argument("--workers", type=int, default=4, help="Number of parallel workers.")
    args = parser.parse_args()
    main(
        generated_path=args.generated_path,
        out_judged_path=args.out_judged_path,
        num_workers=args.workers,
    )