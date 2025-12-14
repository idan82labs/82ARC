#!/usr/bin/env python3
"""
ARC-AGI-2 benchmark runner with pass@K evaluation.

This script evaluates 82ARC against the ARC-AGI-2 dataset (public eval set).
It computes pass@K (default K=2) which matches ARC Prize evaluation rules.

Usage:
    # Clone ARC-AGI-2 dataset first:
    # git clone https://github.com/arcprize/ARC-AGI-2.git

    # Run on public eval (120 tasks):
    python arcagi2_benchmark.py \
        --tasks-dir ../ARC-AGI-2/data/evaluation \
        --num-tasks 120 \
        --pass-k 2 \
        --out results/arcagi2_public_eval.jsonl

    # Quick test (5 tasks):
    python arcagi2_benchmark.py \
        --tasks-dir ../ARC-AGI-2/data/evaluation \
        --num-tasks 5 \
        --pass-k 2

References:
    - ARC-AGI-2 dataset: https://github.com/arcprize/ARC-AGI-2
    - ARC Prize rules: https://arcprize.org/
    - pass@2 evaluation: systems get 2 attempts per test input
"""
import argparse
import asyncio
import json
import os
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

load_dotenv(override=True)

from arc_solver.models import ARCTask, ARCGrid, ARCPair
from arc_solver.services.orchestrator import get_orchestrator


def _load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _to_grid_list(x: Any) -> Optional[List[List[int]]]:
    """
    Normalizes different possible prediction formats into List[List[int]].
    Handles:
      - ARCGrid objects (with to_list(), .grid, .data, or .cells)
      - raw python lists
    """
    if x is None:
        return None

    # ARCGrid likely provides to_list()
    if hasattr(x, "to_list") and callable(getattr(x, "to_list")):
        return x.to_list()

    # Common pattern: ARCGrid.grid, .data, or .cells
    for attr in ("grid", "data", "cells"):
        if hasattr(x, attr):
            v = getattr(x, attr)
            if isinstance(v, list):
                return v

    if isinstance(x, list):
        return x

    return None


def _exact_match(pred: Optional[List[List[int]]], gold: List[List[int]]) -> bool:
    return pred == gold


def _cell_accuracy(pred: Optional[List[List[int]]], gold: List[List[int]]) -> float:
    """
    Debug metric: per-cell accuracy. If shape differs or pred is None => 0.
    """
    if pred is None:
        return 0.0
    if len(pred) != len(gold):
        return 0.0
    if len(gold) > 0 and len(pred) > 0 and len(pred[0]) != len(gold[0]):
        return 0.0
    total = 0
    correct = 0
    for r in range(len(gold)):
        for c in range(len(gold[0])):
            total += 1
            if r < len(pred) and c < len(pred[r]):
                correct += int(pred[r][c] == gold[r][c])
    return correct / total if total else 0.0


def _build_task(task_id: str, task_json: Dict[str, Any]) -> Tuple[ARCTask, List[List[List[int]]]]:
    """
    Build ARCTask from JSON and extract gold outputs for scoring.
    """
    train_pairs: List[ARCPair] = []
    for p in task_json["train"]:
        train_pairs.append(
            ARCPair(
                input=ARCGrid.from_list(p["input"]),
                output=ARCGrid.from_list(p["output"]),
            )
        )

    # For ARC-AGI-2 eval jsons, test includes both input & output.
    # We keep gold outputs for scoring, but only pass inputs into solver.
    test_inputs: List[ARCGrid] = []
    gold_outputs: List[List[List[int]]] = []
    for p in task_json["test"]:
        test_inputs.append(ARCGrid.from_list(p["input"]))
        gold_outputs.append(p["output"])

    return (
        ARCTask(task_id=task_id, train_pairs=train_pairs, test_inputs=test_inputs),
        gold_outputs,
    )


async def _solve_once(orchestrator: Any, task: ARCTask, strategy: str = "default") -> Any:
    """
    Run the solver once on a task.
    """
    workspace = orchestrator.create_workspace(task, strategy)
    result = await orchestrator.solve(workspace.workspace_id)
    return result


def _pick_task_files(tasks_dir: Path, num_tasks: int, seed: int, shuffle: bool) -> List[Path]:
    """
    Get task files, optionally shuffled.
    """
    files = sorted(tasks_dir.glob("*.json"))
    if shuffle:
        rng = random.Random(seed)
        rng.shuffle(files)
    return files[:num_tasks] if num_tasks > 0 else files


def _extract_predictions(result: Any) -> List[Optional[List[List[int]]]]:
    """
    Extract predictions from solver result, handling various output formats.
    """
    preds_raw = getattr(result, "predictions", None)
    preds: List[Optional[List[List[int]]]] = []

    if preds_raw is None:
        return preds

    if isinstance(preds_raw, list):
        for pr in preds_raw:
            # Handle nested list (multiple predictions per test input)
            if isinstance(pr, list) and len(pr) > 0:
                # Take first prediction if it's a list of predictions
                if isinstance(pr[0], list) and len(pr[0]) > 0 and isinstance(pr[0][0], list):
                    preds.append(_to_grid_list(pr[0]))
                else:
                    preds.append(_to_grid_list(pr))
            else:
                preds.append(_to_grid_list(pr))
    else:
        preds = [_to_grid_list(preds_raw)]

    return preds


async def main():
    parser = argparse.ArgumentParser(
        description="ARC-AGI-2 benchmark runner (pass@K) for 82ARC.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick test (5 tasks)
  python arcagi2_benchmark.py --tasks-dir ../ARC-AGI-2/data/evaluation --num-tasks 5

  # Full public eval (120 tasks)
  python arcagi2_benchmark.py --tasks-dir ../ARC-AGI-2/data/evaluation --num-tasks 120 --pass-k 2

  # Run with thorough strategy
  python arcagi2_benchmark.py --tasks-dir ../ARC-AGI-2/data/evaluation --strategy thorough
        """
    )
    parser.add_argument(
        "--tasks-dir", type=str, required=True,
        help="Directory with ARC-AGI-2 task JSONs (e.g., ../ARC-AGI-2/data/evaluation)"
    )
    parser.add_argument(
        "--num-tasks", type=int, default=120,
        help="How many tasks to run. Use 0 for all. (default: 120)"
    )
    parser.add_argument(
        "--pass-k", type=int, default=2,
        help="Number of attempts per task for pass@K. (default: 2)"
    )
    parser.add_argument(
        "--strategy", type=str, default="default",
        choices=["fast", "default", "thorough"],
        help="Strategy profile to use. (default: default)"
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Seed for task shuffling and attempt diversification. (default: 42)"
    )
    parser.add_argument(
        "--shuffle", action="store_true",
        help="Shuffle task order."
    )
    parser.add_argument(
        "--out", type=str, default="results/arcagi2_public_eval.jsonl",
        help="JSONL output path. (default: results/arcagi2_public_eval.jsonl)"
    )
    parser.add_argument(
        "--sleep-between-attempts", type=float, default=1.0,
        help="Delay (seconds) between attempts to reduce provider throttling. (default: 1.0)"
    )
    parser.add_argument(
        "--sleep-between-tasks", type=float, default=0.5,
        help="Delay (seconds) between tasks. (default: 0.5)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Print detailed output per task."
    )
    args = parser.parse_args()

    tasks_dir = Path(args.tasks_dir).expanduser().resolve()
    out_path = Path(args.out).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if not tasks_dir.exists():
        raise SystemExit(f"Tasks directory not found: {tasks_dir}")

    task_files = _pick_task_files(tasks_dir, args.num_tasks, args.seed, args.shuffle)
    if not task_files:
        raise SystemExit(f"No .json tasks found in {tasks_dir}")

    print(f"=" * 60)
    print(f"ARC-AGI-2 Benchmark (pass@{args.pass_k})")
    print(f"=" * 60)
    print(f"Tasks directory: {tasks_dir}")
    print(f"Number of tasks: {len(task_files)}")
    print(f"Strategy: {args.strategy}")
    print(f"Output: {out_path}")
    print(f"=" * 60)

    orchestrator = get_orchestrator()

    solved = 0
    total = 0

    # Aggregated telemetry
    agg_cost_usd = 0.0
    agg_tokens = 0
    agg_api_calls = 0

    t0 = time.time()
    with out_path.open("w", encoding="utf-8") as outf:
        for idx, tf in enumerate(task_files):
            task_id = tf.stem
            task_json = _load_json(tf)
            task, gold_outputs = _build_task(task_id, task_json)

            total += 1
            task_record: Dict[str, Any] = {
                "task_id": task_id,
                "file": str(tf),
                "pass_k": args.pass_k,
                "strategy": args.strategy,
                "num_test_cases": len(gold_outputs),
                "attempts": [],
                "solved": False,
                "solved_attempt": None,
            }

            # pass@K: solved if ANY attempt solves ALL test cases exactly.
            for attempt_idx in range(args.pass_k):
                # Diversity: vary seed per attempt
                attempt_seed = args.seed + attempt_idx * 1000 + idx
                os.environ["ARC_BENCH_SEED"] = str(attempt_seed)
                random.seed(attempt_seed)

                attempt_start = time.time()
                try:
                    result = await _solve_once(orchestrator, task, args.strategy)
                    preds = _extract_predictions(result)
                    error_msg = None
                except Exception as e:
                    preds = []
                    error_msg = str(e)
                    result = None

                attempt_duration = time.time() - attempt_start

                # Evaluate exact match across all test pairs
                exacts = []
                accs = []
                for i, gold in enumerate(gold_outputs):
                    pred_i = preds[i] if i < len(preds) else None
                    exacts.append(_exact_match(pred_i, gold))
                    accs.append(_cell_accuracy(pred_i, gold))

                attempt_payload: Dict[str, Any] = {
                    "attempt": attempt_idx + 1,
                    "exact_per_test": exacts,
                    "cell_acc_per_test": accs,
                    "all_exact": all(exacts) if exacts else False,
                    "duration_seconds": attempt_duration,
                }

                if error_msg:
                    attempt_payload["error"] = error_msg

                # Extract telemetry from result
                if result is not None:
                    metrics = getattr(result, "metrics", None)
                    if metrics:
                        attempt_payload["tokens_used"] = getattr(metrics, "tokens_used", 0)
                        attempt_payload["cost_usd"] = getattr(metrics, "cost_usd", 0.0)
                        attempt_payload["api_calls"] = getattr(metrics, "api_calls", 0)
                        attempt_payload["iterations"] = getattr(metrics, "iterations", 0)

                task_record["attempts"].append(attempt_payload)

                if attempt_payload["all_exact"]:
                    task_record["solved"] = True
                    task_record["solved_attempt"] = attempt_idx + 1
                    break

                if args.sleep_between_attempts > 0 and attempt_idx < args.pass_k - 1:
                    await asyncio.sleep(args.sleep_between_attempts)

            if task_record["solved"]:
                solved += 1

            # Aggregate telemetry from all attempts
            for a in task_record["attempts"]:
                agg_cost_usd += a.get("cost_usd", 0.0)
                agg_tokens += a.get("tokens_used", 0)
                agg_api_calls += a.get("api_calls", 0)

            outf.write(json.dumps(task_record) + "\n")
            outf.flush()

            # Progress output
            status = "✓ SOLVED" if task_record["solved"] else "✗ failed"
            attempt_info = f"(attempt {task_record['solved_attempt']})" if task_record["solved"] else ""
            print(f"[{total:03d}/{len(task_files):03d}] {task_id}: {status} {attempt_info}")

            if args.verbose:
                for a in task_record["attempts"]:
                    acc_str = ", ".join(f"{acc:.1%}" for acc in a["cell_acc_per_test"])
                    print(f"    Attempt {a['attempt']}: exact={a['exact_per_test']}, acc=[{acc_str}]")

            if args.sleep_between_tasks > 0:
                await asyncio.sleep(args.sleep_between_tasks)

    elapsed = time.time() - t0
    score = (solved / total * 100) if total else 0.0
    cost_per_task = agg_cost_usd / total if total else 0.0

    summary = {
        "benchmark": "ARC-AGI-2 Public Eval",
        "tasks_dir": str(tasks_dir),
        "num_tasks": total,
        "pass_k": args.pass_k,
        "strategy": args.strategy,
        "solved": solved,
        "score_percent": score,
        "cost_usd_total": agg_cost_usd,
        "cost_usd_per_task": cost_per_task,
        "tokens_total": agg_tokens,
        "api_calls_total": agg_api_calls,
        "elapsed_seconds": elapsed,
        "results_jsonl": str(out_path),
    }

    print()
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Tasks:           {solved}/{total} solved")
    print(f"Score:           {score:.1f}% (pass@{args.pass_k})")
    print(f"Total cost:      ${agg_cost_usd:.4f}")
    print(f"Cost per task:   ${cost_per_task:.4f}")
    print(f"Total tokens:    {agg_tokens:,}")
    print(f"Total API calls: {agg_api_calls:,}")
    print(f"Elapsed time:    {elapsed:.1f}s ({elapsed/60:.1f} min)")
    print(f"Results saved:   {out_path}")
    print("=" * 60)

    # Also save summary as JSON
    summary_path = out_path.with_suffix(".summary.json")
    with summary_path.open("w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(f"Summary saved:   {summary_path}")


if __name__ == "__main__":
    asyncio.run(main())
