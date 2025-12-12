#!/usr/bin/env python3
"""
HumanEval Benchmark - Code generation benchmark for testing LLMs.
Uses pass@1 with greedy decoding.
"""
import asyncio
import re
import json
import tempfile
import subprocess
from datetime import datetime
from typing import List, Dict, Any, Optional
from datasets import load_dataset
from dotenv import load_dotenv

load_dotenv(override=True)

from arc_solver.config import load_config, RESULTS_DIR
load_config.cache_clear()

from arc_solver.services.llm_client import get_llm_client, Message
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

def resolve_model_name(role: str) -> str:
    """Resolve a role name to actual model name."""
    cfg = load_config()
    role_to_model = {
        "solver": cfg.models.solver,
        "reasoner": cfg.models.reasoner,
        "critic": cfg.models.critic,
        "verifier": cfg.models.verifier,
        "mcts_solver": cfg.models.mcts_solver,
    }
    return role_to_model.get(role, role)

# Prompt for code completion
SYSTEM_PROMPT = """You are a Python coding assistant. Complete the given function based on its docstring.
Return ONLY the Python code, no explanations or markdown. Complete the entire function body."""


def extract_code(response: str, entry_point: str) -> str:
    """Extract the function code from response."""
    # Remove markdown code blocks if present
    response = re.sub(r'```python\s*', '', response)
    response = re.sub(r'```\s*', '', response)

    # Try to find the function definition
    pattern = rf'(def\s+{re.escape(entry_point)}\s*\([^)]*\)[^:]*:.*?)(?=\ndef\s|\nclass\s|\Z)'
    match = re.search(pattern, response, re.DOTALL)
    if match:
        return match.group(1).strip()

    # If no match, return cleaned response
    return response.strip()


def run_code_test(code: str, test: str, timeout: int = 5) -> tuple[bool, str]:
    """Run code with test cases and return (passed, error_msg)."""
    full_code = code + "\n\n" + test

    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(full_code)
            f.flush()

            result = subprocess.run(
                ['python3', f.name],
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode == 0:
                return True, ""
            else:
                error = result.stderr or result.stdout
                return False, error[:500]
    except subprocess.TimeoutExpired:
        return False, "Timeout"
    except Exception as e:
        return False, str(e)[:500]


async def evaluate_problem(
    client,
    prompt: str,
    test: str,
    entry_point: str,
    model_name: str
) -> Dict[str, Any]:
    """Evaluate a single HumanEval problem."""
    messages = [
        Message(role="system", content=SYSTEM_PROMPT),
        Message(role="user", content=f"Complete this Python function:\n\n{prompt}")
    ]

    try:
        response = await client.complete(messages, model_name)
        response_text = response.content

        # Extract the code
        code = extract_code(response_text, entry_point)

        # Run the test
        passed, error = run_code_test(code, test)

        return {
            "entry_point": entry_point,
            "passed": passed,
            "error": error if not passed else None,
            "code": code[:500] if code else None
        }
    except Exception as e:
        return {
            "entry_point": entry_point,
            "passed": False,
            "error": str(e)[:500],
            "code": None
        }


async def run_humaneval_benchmark(
    num_problems: int = 50,
    model: str = "solver"
) -> Dict[str, Any]:
    """Run HumanEval benchmark."""

    model_name = resolve_model_name(model)

    console.print(f"\n[bold]HumanEval Benchmark[/bold]")
    console.print(f"Problems: {num_problems}")
    console.print(f"Model: {model_name}\n")

    # Load dataset
    console.print("[dim]Loading HumanEval dataset...[/dim]")
    dataset = load_dataset('openai/openai_humaneval', split=f'test[:{num_problems}]')

    # Initialize client
    client = await get_llm_client()

    results = {
        "timestamp": datetime.now().isoformat(),
        "benchmark": "HumanEval",
        "model": model_name,
        "num_problems": num_problems,
        "problems": [],
        "passed": 0,
        "total": 0,
        "pass_at_1": 0.0
    }

    with Progress() as progress:
        task = progress.add_task("[cyan]Solving problems...", total=num_problems)

        for i, item in enumerate(dataset):
            prompt = item['prompt']
            test = item['test']
            entry_point = item['entry_point']

            result = await evaluate_problem(client, prompt, test, entry_point, model_name)
            results["problems"].append(result)
            results["total"] += 1

            if result["passed"]:
                results["passed"] += 1
                status = "[green]✓[/green]"
            else:
                status = "[red]✗[/red]"

            console.print(f"  {i+1}. {status} {entry_point}")
            progress.update(task, advance=1)

    # Calculate pass@1
    results["pass_at_1"] = (results["passed"] / results["total"] * 100) if results["total"] > 0 else 0

    # Print summary
    table = Table(title="HumanEval Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Problems", str(results["total"]))
    table.add_row("Passed", str(results["passed"]))
    table.add_row("Pass@1", f"{results['pass_at_1']:.1f}%")

    console.print(table)

    # Reference scores
    console.print("\n[dim]Reference scores (pass@1):[/dim]")
    console.print("[dim]  GPT-4o: ~90%  |  Claude-3.5: ~92%  |  Qwen2.5-Coder-7B: ~85%  |  Qwen2.5-Coder-32B: ~93%[/dim]")

    # Save results
    results_file = RESULTS_DIR / f"humaneval_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"\n[dim]Results saved to: {results_file}[/dim]")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="HumanEval Code Benchmark")
    parser.add_argument("--num-problems", "-n", type=int, default=50,
                       help="Number of problems to test")
    parser.add_argument("--model", "-m", default="solver",
                       help="Model role to use (solver, mcts_solver, etc.)")

    args = parser.parse_args()

    asyncio.run(run_humaneval_benchmark(
        num_problems=args.num_problems,
        model=args.model
    ))
