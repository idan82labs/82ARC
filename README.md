# 82ARC: Small Models, Smart Orchestration

A research implementation exploring whether intelligent orchestration of small language models (7B-32B parameters) can match or exceed the performance of frontier models (200B+ parameters) on the ARC-AGI benchmark.

## Thesis

The prevailing approach to improving AI benchmark performance is to scale model size. We investigate an alternative hypothesis: **strategic orchestration of multiple small, specialized models can achieve competitive results at a fraction of the computational cost**.

This project implements a multi-agent system combining:
- Monte Carlo Tree Search (MCTS) for hypothesis exploration
- Multi-model orchestration with role specialization
- Real code execution and validation feedback loops
- Iterative refinement based on execution results

## The ARC-AGI Challenge

The Abstraction and Reasoning Corpus (ARC) is a benchmark designed to measure general intelligence through visual reasoning puzzles. Each puzzle presents input-output grid pairs demonstrating a transformation rule. The challenge is to infer the rule and apply it to new test inputs.

ARC is particularly interesting because:
- It resists memorization (each puzzle is unique)
- It requires genuine abstraction and reasoning
- Current large language models struggle despite their scale
- Human performance significantly exceeds AI performance

## Architecture Overview

```
                    +------------------+
                    |   Orchestrator   |
                    +--------+---------+
                             |
         +-------------------+-------------------+
         |                   |                   |
    +----v----+        +-----v-----+       +-----v-----+
    |  MCTS   |        |  Solver   |       |  Critic   |
    | Service |        |  (32B)    |       |  (7B)     |
    +----+----+        +-----------+       +-----------+
         |
    +----v----+
    | Reasoner|
    |  (7B)   |
    +---------+
         |
    +----v--------+
    | Code        |
    | Executor    |
    | (Sandbox)   |
    +-------------+
```

### Components

**Orchestrator**: Coordinates the solving process, manages iteration cycles, and aggregates results from multiple hypotheses.

**MCTS Service**: Explores the space of possible transformation strategies using Monte Carlo Tree Search. Generates strategy nodes (high-level approaches) and expands them into executable code. Critically, node evaluation uses **real code execution** against training examples, not heuristics.

**Solver (32B)**: The primary code generation model. Responsible for translating strategies into Python transformation functions.

**Reasoner (7B)**: Generates high-level strategies and analyzes patterns in the input-output pairs.

**Critic (7B)**: Evaluates hypotheses, identifies failure modes, and suggests improvements.

**Code Executor**: Sandboxed execution environment that validates generated code against training examples, providing real feedback for MCTS scoring.

## Key Design Decisions

### Small Models by Design

All models in the system are intentionally small (December 2025 configuration):

| Role | Model | Parameters |
|------|-------|------------|
| Solver | Qwen3-Coder-32B | 32B |
| Reasoner | Qwen3-8B | 8B |
| Critic | DeepSeek-R1-32B | 32B |
| Verifier | Llama-4-Scout-8B | 8B |
| MCTS Solver | Qwen3-7B | 7B |

This contrasts with approaches using GPT-5.2 or other frontier models (estimated 2T+ parameters).

### Real Execution, Not Heuristics

A critical design principle is that all code evaluation uses **actual execution** against training examples. The MCTS simulation phase:

1. Executes generated code in a sandboxed environment
2. Compares outputs against expected results
3. Returns pass rate as the node score (0.0 to 1.0)

This grounds the search in reality rather than proxy metrics.

### Multi-Provider Infrastructure

The system supports multiple LLM providers for cost optimization and rate limit management:

- **Groq**: Fast inference for code generation
- **Together AI**: Cost-effective for reasoning and MCTS exploration
- **OpenRouter**: Access to diverse model ecosystem
- **Fireworks AI**: Fast inference alternative
- **OpenAI**: GPT models (optional)
- **Anthropic**: Claude models (optional)

## Installation

### Prerequisites

- Python 3.10+
- API keys for at least one provider (Groq or Together AI recommended)

### Setup

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/82ARC.git
cd 82ARC

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env with your API keys
```

### Environment Variables

```bash
# Recommended: Both providers for optimal performance
GROQ_API_KEY=your_groq_key
TOGETHER_API_KEY=your_together_key

# Optional
OPENROUTER_API_KEY=your_openrouter_key
FIREWORKS_API_KEY=your_fireworks_key
OPENAI_API_KEY=your_openai_key
ANTHROPIC_API_KEY=your_anthropic_key
```

## Usage

### Command Line Interface

```bash
# Solve a sample task
python -m arc_solver.cli solve --sample horizontal_flip

# Solve from file
python -m arc_solver.cli solve --task path/to/task.json

# List available samples
python -m arc_solver.cli list-samples

# Check configuration
python -m arc_solver.cli check

# Start API server
python -m arc_solver.cli serve
```

### Running Benchmarks

```bash
# Run on ARC training set
python benchmark.py --num-tasks 10

# Run with specific strategy
python benchmark.py --num-tasks 10 --strategy thorough
```

### REST API

```bash
# Start server
uvicorn arc_solver.main:app --reload

# Health check
curl http://localhost:8000/healthz

# Solve a task
curl -X POST http://localhost:8000/api/v1/solve/quick \
  -H "Content-Type: application/json" \
  -d '{
    "train": [
      {"input": [[1,2,3]], "output": [[3,2,1]]},
      {"input": [[4,5]], "output": [[5,4]]}
    ],
    "test": [[[1,2]]]
  }'
```

### Python API

```python
import asyncio
from arc_solver.models import ARCTask, ARCGrid, ARCPair
from arc_solver.services.orchestrator import get_orchestrator

async def solve_task():
    task = ARCTask(
        task_id="my_task",
        train_pairs=[
            ARCPair(
                input=ARCGrid.from_list([[1, 2, 3]]),
                output=ARCGrid.from_list([[3, 2, 1]])
            )
        ],
        test_inputs=[ARCGrid.from_list([[4, 5, 6]])]
    )

    orchestrator = get_orchestrator()
    workspace = orchestrator.create_workspace(task)
    result = await orchestrator.solve(workspace.workspace_id)

    print(f"Solved: {result.is_solved}")
    print(f"Predictions: {result.predictions}")

asyncio.run(solve_task())
```

## Configuration

### Strategy Profiles

| Profile | Budget | Iterations | Use Case |
|---------|--------|------------|----------|
| `fast` | $2 | 5 | Quick exploration |
| `default` | $5 | 10 | Balanced |
| `thorough` | $10 | 15 | Complex tasks |

Configuration is managed via YAML files. See `configs/default.yaml`:

```yaml
models:
  solver: qwen3-coder-32b-groq      # 32B - code generation (Qwen 3)
  reasoner: qwen3-8b-groq            # 8B - reasoning (Qwen 3)
  critic: deepseek-r1-32b            # 32B - critique/review (DeepSeek R1)
  verifier: llama4-scout-8b-groq     # 8B - verification (Llama 4 Scout)
  mcts_solver: qwen3-7b-together     # 7B - MCTS tactic generation (Qwen 3)

strategies:
  default:
    solver:
      max_iterations: 10
      max_hypotheses_per_iteration: 3
    mcts:
      max_iterations: 5
      exploration_weight: 1.41
```

## Project Structure

```
82ARC/
├── arc_solver/
│   ├── __init__.py
│   ├── config.py               # Configuration management
│   ├── main.py                 # FastAPI application
│   ├── cli.py                  # CLI entry point
│   ├── models/
│   │   └── __init__.py         # Domain models (ARCTask, Workspace, etc.)
│   ├── services/
│   │   ├── llm_client.py       # Multi-provider LLM client
│   │   ├── orchestrator.py     # Main solving orchestrator
│   │   └── mcts_service.py     # Hierarchical MCTS with real execution
│   ├── tools/
│   │   ├── grid_analyzer.py    # Grid analysis and pattern detection
│   │   └── code_executor.py    # Sandboxed code execution
│   └── memory/
│       └── cot_log.py          # Chain-of-thought logging
├── configs/
│   └── default.yaml            # Default configuration
├── benchmark.py                # ARC benchmark runner
├── gsm8k_benchmark.py          # GSM8K math benchmark
├── humaneval_benchmark.py      # HumanEval code benchmark
├── tests/
│   └── test_all.py
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## Pipeline Stages

1. **Analysis**: Grid analysis extracts objects, symmetries, colors, and patterns
2. **MCTS Exploration**: Tree search generates and evaluates transformation strategies
3. **Hypothesis Generation**: LLM proposes transformation rules
4. **Code Generation**: Convert hypotheses to Python implementations
5. **Validation**: Execute code against all training examples (real execution)
6. **Revision**: Iteratively fix failures with actual vs expected feedback
7. **Critic Review**: Detect loops and suggest pivots
8. **Prediction**: Apply best solution to test inputs

## Research Context

This project builds on several research directions:

- **Tree of Thoughts** (Yao et al., 2023): Using tree search for LLM reasoning
- **Self-Consistency** (Wang et al., 2023): Sampling multiple reasoning paths
- **Program Synthesis for ARC**: Using code as the hypothesis representation
- **Mixture of Agents**: Orchestrating multiple specialized models

### Comparison to Other Approaches

| System | Approach | Model Size | Est. Accuracy |
|--------|----------|------------|---------------|
| Frontier APIs (GPT-5.2) | Single large model | 2T+ | 50-60% |
| NVARC | Custom training | 7B-70B | 24% |
| ARChitects (TTT) | Test-time training | Variable | 53.5% |
| **82ARC** | Multi-agent orchestration | 7B-32B | In development |

## Limitations

- Current implementation is a research prototype
- Rate limits from free API tiers constrain parallel exploration
- Some ARC puzzles require visual reasoning beyond current capabilities
- Performance varies significantly across puzzle types

## Contributing

Contributions are welcome. Areas of particular interest:

1. Improved MCTS exploration strategies
2. Better prompt engineering for small models
3. Additional grid analysis heuristics
4. Support for more LLM providers
5. Benchmark result collection

## Citation

If you use this work in your research:

```bibtex
@software{82arc2025,
  title={82ARC: Small Models, Smart Orchestration for ARC-AGI},
  year={2025},
  url={https://github.com/idan82labs/82ARC}
}
```

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Francois Chollet for the ARC-AGI benchmark
- The open-source LLM community for accessible models
- Groq, Together AI, and other providers for inference infrastructure
- Research teams behind MindsAI, NVARC, SOAR, and ARChitects
