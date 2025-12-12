#!/usr/bin/env python3
"""
Benchmark script for ARC-AGI evaluation.
Runs the solver on multiple tasks and reports accuracy.
"""
import asyncio
import json
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from dotenv import load_dotenv

load_dotenv(override=True)

from arc_solver.config import load_config, DATA_DIR, RESULTS_DIR

# Clear config cache to ensure fresh config is loaded
load_config.cache_clear()
from arc_solver.models import ARCTask, ARCPair, ARCGrid
from arc_solver.services.orchestrator import get_orchestrator
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, TaskID
from rich.panel import Panel

console = Console()

async def run_benchmark(
    task_dir: str = "training",
    num_tasks: int = 10,
    strategy: str = "fast",
    start_idx: int = 0
) -> Dict[str, Any]:
    """Run benchmark on ARC tasks."""

    # Get task files
    data_path = DATA_DIR / task_dir
    if not data_path.exists():
        console.print(f"[red]Data directory not found: {data_path}[/red]")
        return {}

    task_files = sorted(data_path.glob("*.json"))
    task_files = task_files[start_idx:start_idx + num_tasks]

    if not task_files:
        console.print(f"[red]No tasks found in {data_path}[/red]")
        return {}

    console.print(Panel(
        f"[bold]ARC-AGI Benchmark[/bold]\n"
        f"Dataset: {task_dir}\n"
        f"Tasks: {len(task_files)} (starting from #{start_idx})\n"
        f"Strategy: {strategy}",
        title="Configuration"
    ))

    results = {
        "timestamp": datetime.now().isoformat(),
        "dataset": task_dir,
        "strategy": strategy,
        "num_tasks": len(task_files),
        "tasks": [],
        "solved": 0,
        "total": 0,
        "accuracy": 0.0
    }

    orchestrator = get_orchestrator()

    with Progress() as progress:
        task_progress = progress.add_task(
            "[cyan]Solving tasks...",
            total=len(task_files)
        )

        for task_file in task_files:
            task_id = task_file.stem
            progress.update(task_progress, description=f"[cyan]Solving {task_id}...")

            try:
                # Load task
                with open(task_file) as f:
                    data = json.load(f)

                train_pairs = [
                    ARCPair(
                        input=ARCGrid.from_list(p["input"]),
                        output=ARCGrid.from_list(p["output"])
                    )
                    for p in data["train"]
                ]
                test_inputs = [ARCGrid.from_list(t["input"]) for t in data["test"]]
                expected_outputs = [t["output"] for t in data["test"]]

                task = ARCTask(
                    task_id=task_id,
                    train_pairs=train_pairs,
                    test_inputs=test_inputs
                )

                # Create workspace and solve
                ws = orchestrator.create_workspace(task, strategy)
                result_ws = await orchestrator.solve(ws.workspace_id)

                # Check if solved
                solved = False
                if result_ws.predictions:
                    for i, pred_list in enumerate(result_ws.predictions):
                        if i < len(expected_outputs):
                            expected = expected_outputs[i]
                            # Check if any prediction matches
                            for pred in pred_list:
                                # Handle both list and raw predictions
                                if isinstance(pred, list):
                                    if pred == expected:
                                        solved = True
                                        break
                                elif hasattr(pred, 'cells'):
                                    if pred.cells == expected:
                                        solved = True
                                        break
                            if solved:
                                break

                task_result = {
                    "task_id": task_id,
                    "solved": solved,
                    "status": result_ws.status.value if hasattr(result_ws.status, 'value') else str(result_ws.status),
                    "iterations": result_ws.metrics.iterations if result_ws.metrics else 0,
                    "tokens": result_ws.metrics.tokens_used if result_ws.metrics else 0,
                    "cost": result_ws.metrics.cost_usd if result_ws.metrics else 0,
                    "duration": result_ws.metrics.duration_seconds if result_ws.metrics else 0,
                }

                results["tasks"].append(task_result)
                results["total"] += 1
                if solved:
                    results["solved"] += 1

                status_str = "[green]✓[/green]" if solved else "[red]✗[/red]"
                console.print(f"  {task_id}: {status_str}")

            except Exception as e:
                console.print(f"  [red]{task_id}: Error - {e}[/red]")
                results["tasks"].append({
                    "task_id": task_id,
                    "solved": False,
                    "error": str(e)
                })
                results["total"] += 1

            progress.update(task_progress, advance=1)

    # Calculate accuracy
    if results["total"] > 0:
        results["accuracy"] = results["solved"] / results["total"] * 100

    # Print summary
    table = Table(title="Benchmark Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Tasks Attempted", str(results["total"]))
    table.add_row("Tasks Solved", str(results["solved"]))
    table.add_row("Accuracy", f"{results['accuracy']:.1f}%")

    total_tokens = sum(t.get("tokens", 0) for t in results["tasks"])
    total_cost = sum(t.get("cost", 0) for t in results["tasks"])
    total_duration = sum(t.get("duration", 0) for t in results["tasks"])

    table.add_row("Total Tokens", f"{total_tokens:,}")
    table.add_row("Total Cost", f"${total_cost:.4f}")
    table.add_row("Total Duration", f"{total_duration:.1f}s")

    console.print(table)

    # Save results
    results_file = RESULTS_DIR / f"benchmark_{task_dir}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"\n[dim]Results saved to: {results_file}[/dim]")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ARC-AGI Benchmark")
    parser.add_argument("--dataset", "-d", default="training",
                       choices=["training", "evaluation"],
                       help="Dataset to use")
    parser.add_argument("--num-tasks", "-n", type=int, default=10,
                       help="Number of tasks to run")
    parser.add_argument("--strategy", "-s", default="fast",
                       help="Strategy profile")
    parser.add_argument("--start", type=int, default=0,
                       help="Starting task index")

    args = parser.parse_args()

    asyncio.run(run_benchmark(
        task_dir=args.dataset,
        num_tasks=args.num_tasks,
        strategy=args.strategy,
        start_idx=args.start
    ))
