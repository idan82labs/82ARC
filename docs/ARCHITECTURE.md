# 82ARC Architecture

This document provides detailed technical documentation of the 82ARC system architecture.

## System Overview

82ARC is a multi-agent system designed to solve ARC-AGI puzzles using orchestrated small language models. The system combines tree search, code synthesis, and iterative refinement to explore the space of possible transformations.

## Core Components

### 1. Orchestrator (`arc_solver/services/orchestrator.py`)

The Orchestrator is the central coordinator of the solving process. It manages:

- Workspace lifecycle (creation, state tracking, cleanup)
- Iteration cycles with configurable budgets
- Hypothesis generation and evaluation
- Critic feedback integration
- Final prediction assembly

**Key Methods:**

```python
async def solve(workspace_id: str) -> SolveResponse:
    """Main solving entry point. Runs iteration cycles until solved or budget exhausted."""

async def _run_iteration(ws: Workspace, cot: COTLog) -> bool:
    """Single iteration: generate hypotheses, process them, run critic."""

async def _generate_hypotheses(ws: Workspace, cot: COTLog, analysis: str, num_hypotheses: int) -> List[str]:
    """Generate hypotheses using MCTS exploration and LLM."""
```

**Iteration Flow:**

1. Initialize workspace with task
2. Run grid analysis
3. For each iteration:
   - Generate hypotheses via MCTS
   - Process each hypothesis (code generation, validation)
   - Run critic every 2 iterations
   - Check termination conditions
4. Assemble final predictions

### 2. MCTS Service (`arc_solver/services/mcts_service.py`)

Implements hierarchical Monte Carlo Tree Search for strategy exploration.

**Tree Structure:**

```
ROOT
├── STRATEGY: "Detect objects and apply gravity"
│   └── TERMINAL: [Python code]
├── STRATEGY: "Find pattern repetition"
│   └── TERMINAL: [Python code]
└── STRATEGY: "Apply color mapping"
    └── TERMINAL: [Python code]
```

**Key Innovation: Real Execution Scoring**

The `_simulate()` method uses actual code execution rather than heuristics:

```python
def _simulate(self, workspace_id: str, node: MCTSNode) -> float:
    """Evaluate a node by ACTUALLY executing code against training examples."""
    if not node.is_terminal or not node.code_content:
        return 0.0

    train_pairs = self._train_pairs.get(workspace_id)
    executor = self._get_executor()
    result = executor.validate_against_examples(node.code_content, train_pairs)

    # Score = proportion of examples passed
    return result.num_passed / result.num_total
```

**UCT Selection:**

Node selection uses Upper Confidence Bound for Trees:

```
UCT = (value_sum / visits) + C * sqrt(ln(parent_visits) / visits)
```

Where C is the exploration weight (default: 1.41).

### 3. LLM Client (`arc_solver/services/llm_client.py`)

Multi-provider LLM client supporting:

- Groq (OpenAI-compatible)
- Together AI (OpenAI-compatible)
- OpenRouter (OpenAI-compatible)
- Fireworks AI (OpenAI-compatible)
- OpenAI
- Anthropic (separate API format)

**Provider Abstraction:**

```python
class BaseProvider(ABC):
    @abstractmethod
    async def complete(
        self,
        messages: List[Message],
        model_spec: ModelSpec,
        **kwargs
    ) -> LLMResponse:
        pass
```

**Usage Tracking:**

The client tracks token usage and costs:

```python
@dataclass
class TokenUsage:
    input_tokens: int = 0
    output_tokens: int = 0
    total_cost: float = 0.0
    api_calls: int = 0
```

### 4. Code Executor (`arc_solver/tools/code_executor.py`)

Sandboxed execution environment for running generated Python code.

**Execution Modes:**

1. **InProcessExecutor**: Fast but less isolated. Uses restricted globals.
2. **SubprocessExecutor**: Slower but fully isolated. Recommended for untrusted code.

**Safety Measures (InProcess):**

```python
SAFE_BUILTINS = {
    'abs', 'all', 'any', 'bool', 'dict', 'enumerate', 'filter', 'float',
    'int', 'isinstance', 'iter', 'len', 'list', 'map', 'max', 'min',
    'range', 'reversed', 'round', 'set', 'sorted', 'str', 'sum', 'tuple', 'zip',
    # ... (no exec, eval, open, __import__ unrestricted)
}

ALLOWED_MODULES = {
    'numpy', 'copy', 'itertools', 'functools', 'collections', 'math',
    'operator', 'scipy', 'scipy.ndimage'
}
```

**Validation Interface:**

```python
def validate_against_examples(
    self,
    code: str,
    train_pairs: List[ARCPair],
) -> ValidationResult:
    """Validate code against all training examples."""
```

### 5. Grid Analyzer (`arc_solver/tools/grid_analyzer.py`)

Extracts features from input-output grid pairs:

- **Color Analysis**: Unique colors, frequencies, color mapping
- **Object Detection**: Connected components via scipy.ndimage.label
- **Symmetry Detection**: Horizontal, vertical, rotational symmetry
- **Pattern Detection**: Repeated tiles, scaling factors
- **Dimension Analysis**: Size changes, aspect ratios

**Analysis Output:**

```python
@dataclass
class GridAnalysis:
    input_colors: Set[int]
    output_colors: Set[int]
    color_mapping: Optional[Dict[int, int]]
    objects: List[Object]
    symmetries: Dict[str, bool]
    patterns: List[str]
    dimension_change: Tuple[float, float]
```

## Data Models (`arc_solver/models/__init__.py`)

### Core Task Models

```python
class ARCGrid(BaseModel):
    width: int
    height: int
    cells: List[List[int]]  # Values 0-9

class ARCPair(BaseModel):
    input: ARCGrid
    output: ARCGrid

class ARCTask(BaseModel):
    task_id: str
    train_pairs: List[ARCPair]
    test_inputs: List[ARCGrid]
    test_outputs: Optional[List[ARCGrid]]  # None for evaluation
```

### Workspace State

```python
class Workspace(BaseModel):
    workspace_id: str
    task: ARCTask
    status: WorkspaceStatus  # CREATED, RUNNING, SOLVED, FAILED
    cot_log: COTLog
    predictions: List[List[List[List[int]]]]  # Per test input, k predictions
    prediction_confidences: List[List[float]]
    metrics: SolveMetrics
```

### Hypothesis Tracking

```python
class Hypothesis(BaseModel):
    id: str
    description: str
    status: HypothesisStatus  # PROPOSED, TESTING, PASSED, FAILED, REVISED
    code: Optional[str]
    examples_passed: int
    examples_total: int
    confidence: float
    error_summary: Optional[str]
    parent_id: Optional[str]  # For revision chains
```

### MCTS Nodes

```python
class MCTSNode(BaseModel):
    id: str
    type: MCTSNodeType  # ROOT, STRATEGY, TERMINAL
    parent_id: Optional[str]
    children_ids: List[str]
    text_content: str  # Strategy description
    code_content: Optional[str]  # For terminal nodes
    visits: int
    value_sum: float
    is_terminal: bool
    is_expanded: bool
```

## Configuration (`arc_solver/config.py`)

### Model Registry (December 2025)

All models are intentionally small (7B-32B parameters):

```python
MODEL_DEFINITIONS = {
    "qwen3-coder-32b-groq": ModelSpec(
        provider=Provider.GROQ,
        model_id="qwen-3-coder-32b",
        max_tokens=8192,
        temperature=0.7,
        cost_per_million_input=0.29,
        cost_per_million_output=0.59,
    ),
    "qwen3-7b-together": ModelSpec(
        provider=Provider.TOGETHER,
        model_id="Qwen/Qwen3-7B-Instruct",
        max_tokens=8192,
        temperature=0.7,
        cost_per_million_input=0.20,
        cost_per_million_output=0.20,
    ),
    "llama4-scout-8b-groq": ModelSpec(
        provider=Provider.GROQ,
        model_id="llama-4-scout-8b",
        max_tokens=2048,
        temperature=0.2,
        cost_per_million_input=0.05,
        cost_per_million_output=0.08,
    ),
    "deepseek-r1-32b": ModelSpec(
        provider=Provider.TOGETHER,
        model_id="deepseek-ai/DeepSeek-R1-Distill-Qwen-32B",
        max_tokens=8192,
        temperature=0.7,
        cost_per_million_input=0.89,
        cost_per_million_output=0.89,
    ),
    # ...
}
```

### Role Assignments

```yaml
models:
  solver: qwen3-coder-32b-groq      # 32B - Code generation (Qwen 3)
  reasoner: qwen3-8b-groq            # 8B - Strategy generation (Qwen 3)
  critic: deepseek-r1-32b            # 32B - Hypothesis evaluation (DeepSeek R1)
  verifier: llama4-scout-8b-groq     # 8B - Quick validation (Llama 4 Scout)
  mcts_solver: qwen3-7b-together     # 7B - MCTS code generation (Qwen 3)
```

### Strategy Profiles

```python
class StrategyProfile(BaseModel):
    cost_budget_usd: float = 5.0
    solver: SolverConfig
    mcts: MCTSConfig
    augmentation: AugmentationConfig
```

## API Layer (`arc_solver/main.py`)

FastAPI application with endpoints:

```
GET  /healthz              - Health check
GET  /api/v1/config        - Current configuration
POST /api/v1/workspace     - Create workspace
GET  /api/v1/workspace/{id} - Get workspace state
POST /api/v1/solve/quick   - Quick solve (create + solve)
POST /api/v1/solve/{id}    - Solve existing workspace
POST /api/v1/solve/{id}/cancel - Cancel solving
```

## Request/Response Flow

### Solve Request

```
Client                    API                     Orchestrator
  |                        |                           |
  |-- POST /solve/quick -->|                           |
  |                        |-- create_workspace() ---->|
  |                        |<-- workspace_id ----------|
  |                        |-- solve(workspace_id) --->|
  |                        |                           |
  |                        |     [MCTS exploration]    |
  |                        |     [Code generation]     |
  |                        |     [Validation]          |
  |                        |     [Revision cycles]     |
  |                        |                           |
  |                        |<-- SolveResponse ---------|
  |<-- predictions --------|                           |
```

### Internal Solving Flow

```
Orchestrator                MCTS              Executor           LLM
     |                       |                   |                |
     |-- run_iterations ---->|                   |                |
     |                       |-- _expand --------|--------------->|
     |                       |<-- strategies ----|----------------|
     |                       |                   |                |
     |                       |-- _simulate ----->|                |
     |                       |   (execute code)  |                |
     |                       |<-- pass_rate -----|                |
     |                       |                   |                |
     |<-- terminal_nodes ----|                   |                |
     |                       |                   |                |
     |-- process_hypothesis -|-------------------|--------------->|
     |                       |                   |   (refine)     |
     |<------------------- refined_code ---------|----------------|
```

## Error Handling

### Execution Errors

```python
@dataclass
class ExecutionResult:
    success: bool
    output: Optional[Any]
    error: Optional[str]
    error_type: Optional[str]  # "TimeoutError", "RuntimeError", etc.
    execution_time_ms: float
```

### Validation Errors

```python
@dataclass
class ValidationResult:
    all_passed: bool
    num_passed: int
    num_total: int
    results: List[Dict]  # Per-example results with diffs
    error_summary: Optional[str]
```

## Performance Considerations

### Caching

- Code execution results are cached by (code_hash, input_hash)
- LLM client uses singleton pattern
- MCTS service maintains per-workspace traces

### Parallelization

- Multiple hypotheses can be processed in parallel
- MCTS node expansion can run concurrently
- Provider rate limits may constrain parallelism

### Resource Limits

```yaml
tools:
  execution_timeout: 5.0      # seconds
  max_memory_mb: 256          # per execution
  sandbox_mode: inprocess     # or "subprocess"
```

## Extension Points

### Adding New Providers

1. Implement `BaseProvider` interface
2. Register in `provider_classes` dict
3. Add to `_load_from_env()` for auto-configuration

### Adding New Analysis

1. Extend `GridAnalyzer` with new detection methods
2. Update `analyze()` to include new features
3. Modify prompts to utilize new features

### Custom Strategies

1. Define new `StrategyProfile` in config
2. Override specific parameters
3. Select via `--strategy` CLI flag
