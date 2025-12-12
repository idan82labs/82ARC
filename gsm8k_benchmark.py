#!/usr/bin/env python3
"""
GSM8K Benchmark - Grade School Math benchmark for testing reasoning.
Uses chain-of-thought prompting with our LLM client.
"""
import asyncio
import re
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from datasets import load_dataset
from dotenv import load_dotenv

load_dotenv(override=True)

from arc_solver.config import load_config, RESULTS_DIR, ModelsConfig
load_config.cache_clear()

from arc_solver.services.llm_client import get_llm_client, Message

def resolve_model_name(role: str) -> str:
    """Resolve a role name (solver, reasoner, etc.) to actual model name."""
    cfg = load_config()
    role_to_model = {
        "solver": cfg.models.solver,
        "reasoner": cfg.models.reasoner,
        "critic": cfg.models.critic,
        "verifier": cfg.models.verifier,
        "mcts_solver": cfg.models.mcts_solver,
    }
    return role_to_model.get(role, role)  # Return as-is if not a role
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

console = Console()

# Chain-of-thought prompt for math problems
SYSTEM_PROMPT = """You are a helpful assistant that solves math problems step by step.

For each problem:
1. Read the problem carefully
2. Break it down into steps
3. Show your work for each step
4. Give your final numerical answer after "#### "

Example:
Q: Tom has 5 apples. He buys 3 more. How many does he have?
A: Tom starts with 5 apples.
He buys 3 more apples.
Total = 5 + 3 = 8 apples.
#### 8

Always end with "#### " followed by just the number (no units, no extra text)."""


def extract_answer(response: str) -> Optional[str]:
    """Extract the final answer after ####"""
    # Look for #### followed by a number
    match = re.search(r'####\s*(-?[\d,]+(?:\.\d+)?)', response)
    if match:
        # Remove commas from numbers like 1,000
        return match.group(1).replace(',', '')
    return None


def extract_ground_truth(answer: str) -> str:
    """Extract ground truth answer from GSM8K format"""
    # GSM8K answers end with "#### <number>"
    match = re.search(r'####\s*(-?[\d,]+(?:\.\d+)?)', answer)
    if match:
        return match.group(1).replace(',', '')
    return answer.strip()


def normalize_answer(answer: str) -> float:
    """Normalize answer for comparison"""
    try:
        # Handle negative numbers and decimals
        return float(answer.replace(',', ''))
    except (ValueError, AttributeError):
        return float('nan')


async def evaluate_problem(client, question: str, ground_truth: str, model_name: str) -> Dict[str, Any]:
    """Evaluate a single GSM8K problem"""
    messages = [
        Message(role="system", content=SYSTEM_PROMPT),
        Message(role="user", content=f"Solve this problem step by step:\n\n{question}")
    ]

    try:
        response = await client.complete(messages, model_name)
        response_text = response.content
        predicted = extract_answer(response_text)
        expected = extract_ground_truth(ground_truth)

        # Compare numerically
        if predicted:
            pred_val = normalize_answer(predicted)
            exp_val = normalize_answer(expected)
            correct = abs(pred_val - exp_val) < 0.001
        else:
            correct = False

        return {
            "question": question[:100] + "..." if len(question) > 100 else question,
            "expected": expected,
            "predicted": predicted,
            "correct": correct,
            "response": response_text[:500] if response_text else None
        }
    except Exception as e:
        return {
            "question": question[:100] + "...",
            "expected": extract_ground_truth(ground_truth),
            "predicted": None,
            "correct": False,
            "error": str(e)
        }


async def run_gsm8k_benchmark(
    num_problems: int = 50,
    model: str = "solver"
) -> Dict[str, Any]:
    """Run GSM8K benchmark"""

    # Resolve role name to actual model name
    model_name = resolve_model_name(model)

    console.print(f"\n[bold]GSM8K Benchmark[/bold]")
    console.print(f"Problems: {num_problems}")
    console.print(f"Model: {model_name}\n")

    # Load dataset
    console.print("[dim]Loading GSM8K dataset...[/dim]")
    dataset = load_dataset('openai/gsm8k', 'main', split=f'test[:{num_problems}]')

    # Initialize client
    client = await get_llm_client()

    results = {
        "timestamp": datetime.now().isoformat(),
        "benchmark": "GSM8K",
        "model": model_name,
        "num_problems": num_problems,
        "problems": [],
        "correct": 0,
        "total": 0,
        "accuracy": 0.0
    }

    with Progress() as progress:
        task = progress.add_task("[cyan]Solving problems...", total=num_problems)

        for i, item in enumerate(dataset):
            question = item['question']
            answer = item['answer']

            result = await evaluate_problem(client, question, answer, model_name)
            results["problems"].append(result)
            results["total"] += 1

            if result["correct"]:
                results["correct"] += 1
                status = "[green]✓[/green]"
            else:
                status = "[red]✗[/red]"

            console.print(f"  {i+1}. {status} Expected: {result['expected']}, Got: {result['predicted']}")
            progress.update(task, advance=1)

    # Calculate accuracy
    results["accuracy"] = (results["correct"] / results["total"] * 100) if results["total"] > 0 else 0

    # Print summary
    table = Table(title="GSM8K Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Problems", str(results["total"]))
    table.add_row("Correct", str(results["correct"]))
    table.add_row("Accuracy", f"{results['accuracy']:.1f}%")

    console.print(table)

    # Reference scores
    console.print("\n[dim]Reference scores (approximate):[/dim]")
    console.print("[dim]  GPT-4: ~92%  |  Claude-3: ~90%  |  Llama-70B: ~80%  |  Qwen-32B: ~75%[/dim]")

    # Save results
    results_file = RESULTS_DIR / f"gsm8k_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"\n[dim]Results saved to: {results_file}[/dim]")

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="GSM8K Math Benchmark")
    parser.add_argument("--num-problems", "-n", type=int, default=50,
                       help="Number of problems to test")
    parser.add_argument("--model", "-m", default="solver",
                       help="Model role to use (solver, reasoner, etc.)")

    args = parser.parse_args()

    asyncio.run(run_gsm8k_benchmark(
        num_problems=args.num_problems,
        model=args.model
    ))
