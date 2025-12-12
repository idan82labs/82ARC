"""
Command-line interface for ARC Solver.
"""
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional, List
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint
from loguru import logger
from dotenv import load_dotenv

# Load environment variables from .env file (override=True to ensure .env values take precedence)
load_dotenv(override=True)

from .config import load_config, validate_config, DATA_DIR, RESULTS_DIR

# Clear config cache to ensure fresh config is loaded
load_config.cache_clear()
from .models import ARCTask, ARCGrid, ARCPair
from .services.orchestrator import get_orchestrator

app = typer.Typer(
    name="arc-solve",
    help="ARC-AGI Solver using multi-provider LLMs and MCTS"
)
console = Console()

# ============================================================================
# SAMPLE TASKS
# ============================================================================

SAMPLE_TASKS = {
    "simple_copy": {
        "train": [
            {"input": [[1,2],[3,4]], "output": [[1,2],[3,4]]},
            {"input": [[5,6,7],[8,9,0]], "output": [[5,6,7],[8,9,0]]},
        ],
        "test": [[[1,1],[2,2]]]
    },
    "horizontal_flip": {
        "train": [
            {"input": [[1,2,3]], "output": [[3,2,1]]},
            {"input": [[4,5],[6,7]], "output": [[5,4],[7,6]]},
        ],
        "test": [[[1,2],[3,4],[5,6]]]
    },
    "scale_2x": {
        "train": [
            {"input": [[1]], "output": [[1,1],[1,1]]},
            {"input": [[1,2]], "output": [[1,1,2,2],[1,1,2,2]]},
        ],
        "test": [[[3]]]
    },
    "color_swap": {
        "train": [
            {"input": [[1,0],[0,1]], "output": [[2,0],[0,2]]},
            {"input": [[1,1,0]], "output": [[2,2,0]]},
        ],
        "test": [[[0,1,0],[1,0,1]]]
    }
}

# ============================================================================
# HELPERS
# ============================================================================

def format_grid(cells: List[List[int]], colors: bool = True) -> str:
    """Format a grid for display."""
    if not cells:
        return "[]"
    
    color_map = {
        0: "[dim]0[/]",
        1: "[blue]1[/]",
        2: "[red]2[/]",
        3: "[green]3[/]",
        4: "[yellow]4[/]",
        5: "[magenta]5[/]",
        6: "[cyan]6[/]",
        7: "[orange3]7[/]",
        8: "[deep_sky_blue1]8[/]",
        9: "[dark_red]9[/]",
    }
    
    lines = []
    for row in cells:
        if colors:
            line = " ".join(color_map.get(c, str(c)) for c in row)
        else:
            line = " ".join(str(c) for c in row)
        lines.append(line)
    
    return "\n".join(lines)

def load_task_from_file(path: Path) -> ARCTask:
    """Load an ARC task from a JSON file."""
    with open(path) as f:
        data = json.load(f)
    
    # Handle different formats
    if "train" in data:
        train_pairs = []
        for pair in data["train"]:
            inp = ARCGrid.from_list(pair["input"])
            out = ARCGrid.from_list(pair["output"])
            train_pairs.append(ARCPair(input=inp, output=out))
        
        test_inputs = [ARCGrid.from_list(t["input"] if isinstance(t, dict) else t) 
                       for t in data.get("test", [])]
        
        task_id = data.get("task_id", path.stem)
        
        return ARCTask(
            task_id=task_id,
            train_pairs=train_pairs,
            test_inputs=test_inputs
        )
    
    raise ValueError(f"Unrecognized task format in {path}")

def load_sample_task(name: str) -> ARCTask:
    """Load a sample task by name."""
    if name not in SAMPLE_TASKS:
        raise ValueError(f"Unknown sample: {name}. Available: {list(SAMPLE_TASKS.keys())}")
    
    data = SAMPLE_TASKS[name]
    train_pairs = []
    for pair in data["train"]:
        inp = ARCGrid.from_list(pair["input"])
        out = ARCGrid.from_list(pair["output"])
        train_pairs.append(ARCPair(input=inp, output=out))
    
    test_inputs = [ARCGrid.from_list(t) for t in data["test"]]
    
    return ARCTask(
        task_id=name,
        train_pairs=train_pairs,
        test_inputs=test_inputs
    )

# ============================================================================
# COMMANDS
# ============================================================================

@app.command()
def solve(
    task_file: Optional[Path] = typer.Option(None, "--task", "-t", help="Path to task JSON file"),
    sample: Optional[str] = typer.Option(None, "--sample", "-s", help="Sample task name"),
    task_id: Optional[str] = typer.Option(None, "--task-id", "-i", help="Task ID from dataset"),
    strategy: str = typer.Option("default", "--strategy", help="Strategy profile"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output JSON path"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """Solve a single ARC task."""
    if verbose:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG")
    else:
        logger.remove()
        logger.add(sys.stderr, level="WARNING")
    
    # Load task
    if task_file:
        task = load_task_from_file(task_file)
    elif sample:
        task = load_sample_task(sample)
    elif task_id:
        # TODO: Load from dataset
        console.print(f"[red]Loading from dataset not yet implemented[/]")
        raise typer.Exit(1)
    else:
        console.print("[red]Must specify --task, --sample, or --task-id[/]")
        raise typer.Exit(1)
    
    # Display task info
    console.print(Panel(f"[bold]Task: {task.task_id}[/]\nTraining pairs: {task.num_train} | Test inputs: {task.num_test}"))
    
    # Show training examples
    console.print("\n[bold]Training Examples:[/]")
    for i, pair in enumerate(task.train_pairs):
        table = Table(title=f"Example {i+1}", show_header=True)
        table.add_column("Input", justify="left")
        table.add_column("Output", justify="left")
        table.add_row(format_grid(pair.input.cells), format_grid(pair.output.cells))
        console.print(table)
    
    # Validate config
    try:
        validate_config()
    except ValueError as e:
        console.print(f"[red]Configuration error: {e}[/]")
        raise typer.Exit(1)
    
    # Solve
    async def run_solve():
        orchestrator = get_orchestrator()
        ws = orchestrator.create_workspace(task, strategy)
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            progress.add_task(description="Solving...", total=None)
            result = await orchestrator.solve(ws.workspace_id)
        
        return result, orchestrator.get_cot_log(ws.workspace_id)
    
    ws, cot = asyncio.run(run_solve())
    
    # Display results
    console.print("\n[bold]Results:[/]")
    
    status_color = "green" if ws.is_solved else "yellow"
    console.print(f"Status: [{status_color}]{ws.status.value}[/]")
    console.print(f"Solved: {'✓' if ws.is_solved else '✗'}")
    console.print(f"Best Score: {cot.best_score * 100:.0f}%")
    
    metrics_table = Table(title="Metrics")
    metrics_table.add_column("Metric")
    metrics_table.add_column("Value")
    metrics_table.add_row("Iterations", str(ws.metrics.iterations))
    metrics_table.add_row("Tokens", f"{ws.metrics.tokens_used:,}")
    metrics_table.add_row("Cost", f"${ws.metrics.cost_usd:.4f}")
    metrics_table.add_row("Duration", f"{ws.metrics.duration_seconds:.1f}s")
    metrics_table.add_row("Candidates", str(ws.metrics.candidates_generated))
    console.print(metrics_table)
    
    # Show predictions (k=2 per test)
    if ws.predictions:
        console.print("\n[bold]Predictions:[/]")
        for i, test_preds in enumerate(ws.predictions):
            console.print(f"Test {i+1}:")
            for k, pred in enumerate(test_preds):
                conf = ws.prediction_confidences[i][k] if ws.prediction_confidences and i < len(ws.prediction_confidences) else 0.0
                console.print(f"  Attempt {k+1} (confidence: {conf:.2f}):")
                console.print(format_grid(pred))
            console.print()
    
    # Save output
    if output:
        result_data = {
            "task_id": task.task_id,
            "solved": ws.is_solved,
            "predictions": ws.predictions,
            "prediction_confidences": ws.prediction_confidences,
            "metrics": ws.metrics.model_dump(),
            "cot_summary": cot.get_stats(),
        }
        with open(output, "w") as f:
            json.dump(result_data, f, indent=2)
        console.print(f"[dim]Results saved to {output}[/]")

@app.command()
def list_samples():
    """List available sample tasks."""
    table = Table(title="Sample Tasks")
    table.add_column("Name")
    table.add_column("Description")
    table.add_column("Train/Test")
    
    descriptions = {
        "simple_copy": "Identity transformation",
        "horizontal_flip": "Flip grid horizontally",
        "scale_2x": "Scale grid by 2x",
        "color_swap": "Swap color 1 to color 2",
    }
    
    for name, data in SAMPLE_TASKS.items():
        desc = descriptions.get(name, "")
        count = f"{len(data['train'])}/{len(data['test'])}"
        table.add_row(name, desc, count)
    
    console.print(table)

@app.command()
def check():
    """Check configuration and available providers."""
    console.print("[bold]Configuration Check[/]\n")
    
    cfg = load_config()
    
    # Providers
    providers_table = Table(title="Providers")
    providers_table.add_column("Provider")
    providers_table.add_column("Status")
    providers_table.add_column("Base URL")
    
    for name, prov in cfg.providers.items():
        if prov.api_key:
            status = "[green]✓ Configured[/]"
        else:
            status = "[dim]Not configured[/]"
        providers_table.add_row(name, status, prov.base_url or "")
    
    console.print(providers_table)
    
    # Models
    console.print("\n[bold]Model Assignments[/]")
    console.print(f"  Solver: {cfg.models.solver}")
    console.print(f"  Reasoner: {cfg.models.reasoner}")
    console.print(f"  Critic: {cfg.models.critic}")
    console.print(f"  Verifier: {cfg.models.verifier}")
    
    # Validate
    try:
        validate_config()
        console.print("\n[green]✓ Configuration valid[/]")
    except ValueError as e:
        console.print(f"\n[red]✗ Configuration invalid: {e}[/]")

@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", "--host", "-h"),
    port: int = typer.Option(8000, "--port", "-p"),
    reload: bool = typer.Option(False, "--reload", "-r"),
):
    """Start the API server."""
    import uvicorn
    console.print(f"[bold]Starting server at http://{host}:{port}[/]")
    uvicorn.run(
        "arc_solver.main:app",
        host=host,
        port=port,
        reload=reload
    )

@app.command()
def test_components():
    """Run component tests without API keys."""
    console.print("[bold]Running Component Tests[/]\n")
    
    passed = 0
    failed = 0
    
    # Test 1: Imports
    console.print("1. Testing imports...", end=" ")
    try:
        from .config import load_config
        from .models import ARCTask, ARCGrid
        from .tools.grid_analyzer import GridAnalyzer
        from .tools.code_executor import CodeExecutor
        from .memory.cot_log import COTLog
        console.print("[green]✓[/]")
        passed += 1
    except Exception as e:
        console.print(f"[red]✗ {e}[/]")
        failed += 1
    
    # Test 2: Grid Analyzer
    console.print("2. Testing GridAnalyzer...", end=" ")
    try:
        from .tools.grid_analyzer import GridAnalyzer
        analyzer = GridAnalyzer()
        grid = ARCGrid.from_list([[1, 2], [3, 4]])
        analysis = analyzer.analyze(grid)
        assert analysis.height == 2
        assert analysis.width == 2
        assert 1 in analysis.colors_present
        console.print("[green]✓[/]")
        passed += 1
    except Exception as e:
        console.print(f"[red]✗ {e}[/]")
        failed += 1
    
    # Test 3: Code Executor
    console.print("3. Testing CodeExecutor...", end=" ")
    try:
        from .tools.code_executor import CodeExecutor
        executor = CodeExecutor(mode="inprocess")
        code = """
import numpy as np
def transform(input_grid):
    return input_grid.tolist()
"""
        result = executor.execute(code, [[1, 2], [3, 4]])
        assert result.success
        assert result.output == [[1, 2], [3, 4]]
        console.print("[green]✓[/]")
        passed += 1
    except Exception as e:
        console.print(f"[red]✗ {e}[/]")
        failed += 1
    
    # Test 4: COT Log
    console.print("4. Testing COTLog...", end=" ")
    try:
        from .memory.cot_log import COTLog
        from .models import HypothesisStatus
        cot = COTLog("test")
        h = cot.add_hypothesis("Test hypothesis")
        assert h.id is not None
        cot.update_hypothesis(h.id, status=HypothesisStatus.TESTING)
        assert cot.get_hypothesis(h.id).status == HypothesisStatus.TESTING
        console.print("[green]✓[/]")
        passed += 1
    except Exception as e:
        console.print(f"[red]✗ {e}[/]")
        failed += 1
    
    # Test 5: Sample Solutions
    console.print("5. Testing sample solutions...", end=" ")
    try:
        from .tools.code_executor import CodeExecutor
        executor = CodeExecutor(mode="inprocess")
        
        # Test horizontal flip
        code = """
import numpy as np
def transform(input_grid):
    return np.fliplr(input_grid).tolist()
"""
        result = executor.execute(code, [[1, 2, 3]])
        assert result.success
        assert result.output == [[3, 2, 1]]
        
        # Test scale 2x
        code = """
import numpy as np
def transform(input_grid):
    grid = np.array(input_grid)
    return np.repeat(np.repeat(grid, 2, axis=0), 2, axis=1).tolist()
"""
        result = executor.execute(code, [[1]])
        assert result.success
        assert result.output == [[1, 1], [1, 1]]
        
        console.print("[green]✓[/]")
        passed += 1
    except Exception as e:
        console.print(f"[red]✗ {e}[/]")
        failed += 1
    
    # Summary
    console.print(f"\n[bold]Results: Passed {passed}/{passed + failed}[/]")
    
    if failed > 0:
        raise typer.Exit(1)

if __name__ == "__main__":
    app()
