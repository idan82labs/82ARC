"""
RunPod Serverless Handler for 82ARC.

Deploy to RunPod Serverless for simple, scalable ARC task solving.

Setup:
    1. Create RunPod account at runpod.io
    2. Build Docker image: docker build -t 82arc-runpod -f cloud/Dockerfile.runpod .
    3. Push to Docker Hub or RunPod registry
    4. Create Serverless endpoint with your image
    5. Set environment variables: GROQ_API_KEY, TOGETHER_API_KEY
"""
import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Any, Dict

# RunPod handler
try:
    import runpod
except ImportError:
    runpod = None


def init():
    """Initialize the model/environment on cold start."""
    sys.path.insert(0, "/app")
    os.chdir("/app")


async def solve_task(task_data: Dict[str, Any], task_id: str, strategy: str = "default") -> Dict[str, Any]:
    """Solve a single ARC task."""
    from arc_solver.models import ARCTask, ARCPair, ARCGrid
    from arc_solver.services.orchestrator import get_orchestrator

    start_time = datetime.now()

    try:
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

        orchestrator = get_orchestrator()
        ws = orchestrator.create_workspace(task, strategy)
        result_ws = await orchestrator.solve(ws.workspace_id)

        # Extract predictions
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

        duration = (datetime.now() - start_time).total_seconds()

        return {
            "task_id": task_id,
            "solved": solved,
            "status": str(result_ws.status),
            "iterations": result_ws.metrics.iterations if result_ws.metrics else 0,
            "tokens": result_ws.metrics.tokens_used if result_ws.metrics else 0,
            "cost": result_ws.metrics.cost_usd if result_ws.metrics else 0,
            "duration": duration,
            "predictions": predictions[:3],
        }

    except Exception as e:
        return {
            "task_id": task_id,
            "solved": False,
            "error": str(e),
            "duration": (datetime.now() - start_time).total_seconds(),
        }


def handler(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    RunPod serverless handler.

    Input format:
    {
        "input": {
            "task": { "train": [...], "test": [...] },
            "task_id": "optional_id",
            "strategy": "default"
        }
    }
    """
    init()

    job_input = event.get("input", {})
    task_data = job_input.get("task", {})
    task_id = job_input.get("task_id", "runpod_task")
    strategy = job_input.get("strategy", "default")

    if not task_data:
        return {"error": "No task data provided"}

    # Run the async solve function
    result = asyncio.run(solve_task(task_data, task_id, strategy))

    return result


if runpod:
    runpod.serverless.start({"handler": handler})
