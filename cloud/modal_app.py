"""
Modal deployment for 82ARC - Run ARC-AGI 2 benchmark at scale.

Quick Start:
    1. pip install modal
    2. modal setup  # One-time authentication
    3. modal secret create arc-api-keys \
         GROQ_API_KEY=your_groq_key \
         TOGETHER_API_KEY=your_together_key
    4. modal run cloud/modal_app.py --num-tasks 400 --strategy default

For the full ARC-AGI 2 test set:
    modal run cloud/modal_app.py --dataset evaluation --num-tasks 400 --parallel 20
"""
import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import modal

# Define the Modal app
app = modal.App("82arc-benchmark")

# Create the image with all dependencies
image = (
    modal.Image.debian_slim(python_version="3.11")
    .pip_install(
        "fastapi>=0.115.0",
        "uvicorn[standard]>=0.30.0",
        "pydantic>=2.7.0",
        "numpy>=1.26.0",
        "scipy>=1.11.0",
        "httpx>=0.27.0",
        "aiohttp>=3.9.0",
        "PyYAML>=6.0",
        "python-dotenv>=1.0.0",
        "tenacity>=8.2.0",
        "rich>=13.0.0",
        "typer>=0.9.0",
        "loguru>=0.7.0",
    )
    .copy_local_dir("arc_solver", "/app/arc_solver")
    .copy_local_dir("configs", "/app/configs")
    .copy_local_dir("data", "/app/data")
    .workdir("/app")
)

# Volume for persisting results
results_volume = modal.Volume.from_name("arc-results", create_if_missing=True)


@app.function(
    image=image,
    secrets=[modal.Secret.from_name("arc-api-keys")],
    timeout=600,  # 10 minutes per task
    memory=2048,  # 2GB RAM
)
async def solve_single_task(
    task_data: Dict[str, Any],
    task_id: str,
    strategy: str = "default"
) -> Dict[str, Any]:
    """Solve a single ARC task."""
    # Add app to path
    sys.path.insert(0, "/app")

    from arc_solver.models import ARCTask, ARCPair, ARCGrid
    from arc_solver.services.orchestrator import get_orchestrator

    start_time = datetime.now()

    try:
        # Parse task
        train_pairs = [
            ARCPair(
                input=ARCGrid.from_list(p["input"]),
                output=ARCGrid.from_list(p["output"])
            )
            for p in task_data["train"]
        ]
        test_inputs = [ARCGrid.from_list(t["input"]) for t in task_data["test"]]
        expected_outputs = [t.get("output") for t in task_data["test"]]

        task = ARCTask(
            task_id=task_id,
            train_pairs=train_pairs,
            test_inputs=test_inputs
        )

        # Create orchestrator and solve
        orchestrator = get_orchestrator()
        ws = orchestrator.create_workspace(task, strategy)
        result_ws = await orchestrator.solve(ws.workspace_id)

        # Check if solved
        solved = False
        predictions = []

        if result_ws.predictions:
            for i, pred_list in enumerate(result_ws.predictions):
                if i < len(expected_outputs) and expected_outputs[i]:
                    expected = expected_outputs[i]
                    for pred in pred_list:
                        pred_cells = pred if isinstance(pred, list) else getattr(pred, 'cells', None)
                        if pred_cells:
                            predictions.append(pred_cells)
                            if pred_cells == expected:
                                solved = True
                                break

        duration = (datetime.now() - start_time).total_seconds()

        return {
            "task_id": task_id,
            "solved": solved,
            "status": result_ws.status.value if hasattr(result_ws.status, 'value') else str(result_ws.status),
            "iterations": result_ws.metrics.iterations if result_ws.metrics else 0,
            "tokens": result_ws.metrics.tokens_used if result_ws.metrics else 0,
            "cost": result_ws.metrics.cost_usd if result_ws.metrics else 0,
            "duration": duration,
            "predictions": predictions[:3],  # Keep top 3 predictions
        }

    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        return {
            "task_id": task_id,
            "solved": False,
            "error": str(e),
            "duration": duration,
        }


@app.function(
    image=image,
    volumes={"/results": results_volume},
    timeout=7200,  # 2 hours max for full benchmark
)
async def run_benchmark_parallel(
    dataset: str = "training",
    num_tasks: int = 10,
    strategy: str = "default",
    start_idx: int = 0,
    parallel_workers: int = 10,
) -> Dict[str, Any]:
    """Run benchmark with parallel task execution."""
    sys.path.insert(0, "/app")

    from rich.console import Console
    console = Console()

    # Load task files
    data_path = Path("/app/data") / dataset
    if not data_path.exists():
        return {"error": f"Dataset not found: {data_path}"}

    task_files = sorted(data_path.glob("*.json"))
    task_files = task_files[start_idx:start_idx + num_tasks]

    if not task_files:
        return {"error": f"No tasks found in {data_path}"}

    console.print(f"[bold]Starting ARC-AGI Benchmark[/bold]")
    console.print(f"Dataset: {dataset}, Tasks: {len(task_files)}, Strategy: {strategy}")
    console.print(f"Parallel workers: {parallel_workers}")

    # Load all task data
    tasks_to_solve = []
    for task_file in task_files:
        with open(task_file) as f:
            task_data = json.load(f)
        tasks_to_solve.append((task_data, task_file.stem))

    # Run tasks in parallel using Modal's map
    results_list = []

    # Use starmap for parallel execution
    for result in solve_single_task.starmap(
        [(task_data, task_id, strategy) for task_data, task_id in tasks_to_solve],
        return_exceptions=True
    ):
        if isinstance(result, Exception):
            results_list.append({
                "task_id": "unknown",
                "solved": False,
                "error": str(result)
            })
        else:
            results_list.append(result)
            status = "✓" if result.get("solved") else "✗"
            console.print(f"  {result.get('task_id', 'unknown')}: {status}")

    # Aggregate results
    solved_count = sum(1 for r in results_list if r.get("solved"))
    total_count = len(results_list)
    accuracy = (solved_count / total_count * 100) if total_count > 0 else 0

    total_cost = sum(r.get("cost", 0) for r in results_list)
    total_tokens = sum(r.get("tokens", 0) for r in results_list)
    total_duration = sum(r.get("duration", 0) for r in results_list)

    final_results = {
        "timestamp": datetime.now().isoformat(),
        "dataset": dataset,
        "strategy": strategy,
        "num_tasks": total_count,
        "solved": solved_count,
        "accuracy": accuracy,
        "total_cost_usd": total_cost,
        "total_tokens": total_tokens,
        "total_duration_seconds": total_duration,
        "parallel_workers": parallel_workers,
        "tasks": results_list,
    }

    # Save results to volume
    results_file = f"/results/benchmark_{dataset}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, "w") as f:
        json.dump(final_results, f, indent=2)

    console.print(f"\n[bold green]Benchmark Complete![/bold green]")
    console.print(f"Solved: {solved_count}/{total_count} ({accuracy:.1f}%)")
    console.print(f"Total Cost: ${total_cost:.4f}")
    console.print(f"Results saved to: {results_file}")

    return final_results


@app.local_entrypoint()
def main(
    dataset: str = "training",
    num_tasks: int = 10,
    strategy: str = "default",
    start: int = 0,
    parallel: int = 10,
):
    """
    Run 82ARC benchmark on Modal.

    Examples:
        # Run 10 training tasks
        modal run cloud/modal_app.py --num-tasks 10

        # Run full evaluation set with 20 parallel workers
        modal run cloud/modal_app.py --dataset evaluation --num-tasks 400 --parallel 20

        # Run with thorough strategy
        modal run cloud/modal_app.py --num-tasks 50 --strategy thorough
    """
    print(f"Starting 82ARC benchmark on Modal...")
    print(f"  Dataset: {dataset}")
    print(f"  Tasks: {num_tasks}")
    print(f"  Strategy: {strategy}")
    print(f"  Parallel workers: {parallel}")
    print()

    results = run_benchmark_parallel.remote(
        dataset=dataset,
        num_tasks=num_tasks,
        strategy=strategy,
        start_idx=start,
        parallel_workers=parallel,
    )

    print("\n" + "=" * 50)
    print("FINAL RESULTS")
    print("=" * 50)
    print(f"Tasks Solved: {results['solved']}/{results['num_tasks']}")
    print(f"Accuracy: {results['accuracy']:.1f}%")
    print(f"Total Cost: ${results['total_cost_usd']:.4f}")
    print(f"Total Tokens: {results['total_tokens']:,}")

    return results


# Deploy as a web endpoint for API access
@app.function(
    image=image,
    secrets=[modal.Secret.from_name("arc-api-keys")],
)
@modal.web_endpoint(method="POST")
async def solve_task_api(task_json: Dict[str, Any]) -> Dict[str, Any]:
    """
    Web API endpoint for solving individual tasks.

    POST /solve_task_api
    {
        "task": { "train": [...], "test": [...] },
        "strategy": "default"
    }
    """
    task_data = task_json.get("task", {})
    task_id = task_json.get("task_id", "api_task")
    strategy = task_json.get("strategy", "default")

    result = await solve_single_task.remote.aio(task_data, task_id, strategy)
    return result
