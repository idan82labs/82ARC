"""
Hierarchical Monte Carlo Tree Search for ARC strategy exploration.
Explores: Root → Strategies → Tactics → Terminal (code)
"""
import math
import asyncio
from typing import List, Dict, Optional, Any
from loguru import logger

from ..config import load_config, get_strategy
from ..models import MCTSNode, MCTSNodeType, SearchTrace, ARCPair, new_id
from ..tools.code_executor import CodeExecutor
from .llm_client import LLMClient, Message, get_llm_client

# ============================================================================
# PROMPTS
# ============================================================================

STRATEGY_GENERATION_PROMPT = """You are an expert at solving ARC-AGI puzzles. Given the task analysis below, propose 3-5 high-level strategies that could solve this puzzle.

## Task Analysis
{analysis}

## Instructions
Propose distinct strategies. Each strategy should be:
1. A clear high-level approach (e.g., "Detect connected components and apply gravity")
2. Different from other strategies
3. Applicable to the observed patterns

Return ONLY a JSON array of strategy strings:
["Strategy 1 description", "Strategy 2 description", ...]"""

TACTIC_GENERATION_PROMPT = """You are an expert Python programmer for ARC-AGI puzzles.

## Strategy
{strategy}

## Task Analysis
{analysis}

## Instructions
Implement this strategy as a Python function. The function must:
1. Be named `transform`
2. Take a numpy array `input_grid` as input
3. Return the transformed grid as a list of lists

```python
import numpy as np

def transform(input_grid):
    '''Transform the input grid.'''
    grid = np.array(input_grid)
    # Your implementation
    return result.tolist()
```

Return ONLY the Python code, no explanation."""

# ============================================================================
# MCTS SERVICE
# ============================================================================

class MCTSService:
    """
    Hierarchical MCTS for ARC strategy exploration.

    Tree structure:
    - Root: Starting point
    - Strategy nodes: High-level approaches
    - Tactical nodes: Specific implementations
    - Terminal nodes: Executable code
    """

    def __init__(self):
        self._traces: Dict[str, SearchTrace] = {}
        self._client: Optional[LLMClient] = None
        self._executor: Optional[CodeExecutor] = None
        self._train_pairs: Dict[str, List[ARCPair]] = {}  # workspace_id -> training pairs

    def _get_executor(self) -> CodeExecutor:
        if self._executor is None:
            self._executor = CodeExecutor()
        return self._executor
    
    async def _get_client(self) -> LLMClient:
        if self._client is None:
            self._client = await get_llm_client()
        return self._client
    
    def init_search(self, workspace_id: str) -> SearchTrace:
        """Initialize a new search tree."""
        root = MCTSNode(
            id=new_id(),
            type=MCTSNodeType.ROOT,
            text_content="ROOT",
            depth=0
        )
        trace = SearchTrace(
            workspace_id=workspace_id,
            root_id=root.id
        )
        trace.nodes[root.id] = root
        self._traces[workspace_id] = trace
        return trace
    
    def get_trace(self, workspace_id: str) -> Optional[SearchTrace]:
        return self._traces.get(workspace_id)

    def reset_search(self, workspace_id: str) -> None:
        """Reset the search tree for a workspace to force new exploration."""
        if workspace_id in self._traces:
            del self._traces[workspace_id]
            logger.debug(f"Reset MCTS tree for workspace {workspace_id}")

    async def run_iterations(
        self,
        workspace_id: str,
        analysis_context: str,
        num_iterations: int = 5,
        exploration_weight: float = 1.41,
        train_pairs: Optional[List[ARCPair]] = None,
    ) -> SearchTrace:
        """
        Run MCTS iterations.

        Args:
            workspace_id: Workspace ID
            analysis_context: Task analysis for prompting
            num_iterations: Number of MCTS iterations
            exploration_weight: UCT exploration parameter
            train_pairs: Training examples for real code validation
        """
        # Store training pairs for this workspace (required for real evaluation)
        if train_pairs:
            self._train_pairs[workspace_id] = train_pairs

        trace = self._traces.get(workspace_id)
        if not trace:
            trace = self.init_search(workspace_id)
        
        for i in range(num_iterations):
            logger.debug(f"MCTS iteration {i+1}/{num_iterations}")
            
            # 1. Selection
            leaf = self._select(trace, trace.nodes[trace.root_id], exploration_weight)
            
            # 2. Expansion
            if not leaf.is_terminal and not leaf.is_expanded:
                expanded = await self._expand(trace, leaf, analysis_context)
                leaf = expanded if expanded else leaf
            
            # 3. Simulation (evaluation) - REAL code execution against training examples
            value = self._simulate(workspace_id, leaf)
            
            # 4. Backpropagation
            self._backpropagate(trace, leaf, value)
            
            trace.iterations += 1
        
        # Find best leaf
        trace.best_leaf_id = self._find_best_terminal(trace)
        
        return trace
    
    def _select(
        self,
        trace: SearchTrace,
        node: MCTSNode,
        exploration_weight: float
    ) -> MCTSNode:
        """Select most promising node using UCT."""
        while node.is_expanded and not node.is_terminal:
            if not node.children_ids:
                return node
            
            best_child_id = max(
                node.children_ids,
                key=lambda cid: trace.nodes[cid].uct_score(node.visits, exploration_weight)
            )
            node = trace.nodes[best_child_id]
        
        return node
    
    async def _expand(
        self,
        trace: SearchTrace,
        node: MCTSNode,
        context: str
    ) -> Optional[MCTSNode]:
        """Expand node by generating children."""
        node.is_expanded = True
        client = await self._get_client()
        cfg = load_config()
        
        if node.type == MCTSNodeType.ROOT:
            # Generate strategy nodes
            try:
                prompt = STRATEGY_GENERATION_PROMPT.format(analysis=context)
                response = await client.complete(
                    [Message(role="user", content=prompt)],
                    cfg.models.reasoner
                )
                
                # Parse strategies
                import json
                import re

                # Clean thinking model output (remove <think>...</think> blocks)
                content = response.content
                content = re.sub(r'<think>.*?</think>', '', content, flags=re.DOTALL)

                # Try to extract JSON array - find the last complete array
                strategies = []
                matches = re.findall(r'\[(?:[^\[\]]|\[(?:[^\[\]]|\[[^\[\]]*\])*\])*\]', content)
                for match in reversed(matches):
                    try:
                        parsed = json.loads(match)
                        if isinstance(parsed, list) and all(isinstance(s, str) for s in parsed):
                            strategies = parsed
                            break
                    except json.JSONDecodeError:
                        continue

                if not strategies:
                    # Fallback: split by newlines and numbered lists
                    lines = []
                    for line in content.split('\n'):
                        line = line.strip()
                        # Remove numbering like "1.", "2.", "-", "*"
                        line = re.sub(r'^[\d]+[.)\-]\s*', '', line)
                        line = re.sub(r'^[-*]\s*', '', line)
                        if line and len(line) > 10 and not line.startswith('['):
                            lines.append(line)
                    strategies = lines[:5]
                
                created = None
                for strategy in strategies[:5]:
                    if not strategy:
                        continue
                    child = MCTSNode(
                        id=new_id(),
                        type=MCTSNodeType.STRATEGY,
                        parent_id=node.id,
                        text_content=strategy,
                        depth=node.depth + 1
                    )
                    trace.nodes[child.id] = child
                    node.children_ids.append(child.id)
                    created = child
                
                return created
                
            except Exception as e:
                logger.error(f"Strategy generation failed: {e}")
                return None
        
        elif node.type == MCTSNodeType.STRATEGY:
            # Generate tactical (code) node
            # Use mcts_solver (Together AI) to avoid Groq rate limits during parallel MCTS expansion
            try:
                prompt = TACTIC_GENERATION_PROMPT.format(
                    strategy=node.text_content,
                    analysis=context
                )
                response = await client.complete(
                    [Message(role="user", content=prompt)],
                    cfg.models.mcts_solver
                )
                
                # Extract code
                code = self._extract_code(response.content)
                
                child = MCTSNode(
                    id=new_id(),
                    type=MCTSNodeType.TERMINAL,
                    parent_id=node.id,
                    text_content=node.text_content,
                    code_content=code,
                    is_terminal=True,
                    depth=node.depth + 1
                )
                trace.nodes[child.id] = child
                node.children_ids.append(child.id)
                
                return child
                
            except Exception as e:
                logger.error(f"Tactic generation failed: {e}")
                return None
        
        return None
    
    def _simulate(self, workspace_id: str, node: MCTSNode) -> float:
        """
        Evaluate a node by ACTUALLY executing code against training examples.
        Returns value in [0, 1] based on real pass rate.
        """
        if not node.is_terminal or not node.code_content:
            # Non-terminal nodes: return 0 (unknown, needs expansion)
            return 0.0

        # Get training pairs for this workspace
        train_pairs = self._train_pairs.get(workspace_id)
        if not train_pairs:
            logger.warning(f"No training pairs for workspace {workspace_id}, using fallback score")
            # Fallback: basic syntax check only
            return 0.1 if 'def transform' in node.code_content else 0.0

        # REAL EXECUTION: Run code against all training examples
        executor = self._get_executor()
        try:
            result = executor.validate_against_examples(node.code_content, train_pairs)

            # Score = proportion of examples passed
            score = result.num_passed / result.num_total if result.num_total > 0 else 0.0

            logger.debug(
                f"MCTS node {node.id[:8]}: {result.num_passed}/{result.num_total} examples passed "
                f"(score={score:.2f})"
            )

            # Store validation result on node for later reference
            node.validation_score = score
            node.validation_passed = result.num_passed
            node.validation_total = result.num_total

            return score

        except Exception as e:
            logger.error(f"MCTS simulation failed for node {node.id[:8]}: {e}")
            return 0.0  # Execution error = 0 score
    
    def _backpropagate(self, trace: SearchTrace, node: MCTSNode, value: float):
        """Backpropagate value up the tree."""
        current = node
        while current:
            current.visits += 1
            current.value_sum += value
            
            if current.parent_id:
                current = trace.nodes.get(current.parent_id)
            else:
                break
    
    def _find_best_terminal(self, trace: SearchTrace) -> Optional[str]:
        """Find the best terminal node."""
        best_id = None
        best_value = -1
        
        for node in trace.nodes.values():
            if node.is_terminal and node.visits > 0:
                avg_value = node.value_sum / node.visits
                if avg_value > best_value:
                    best_value = avg_value
                    best_id = node.id
        
        return best_id
    
    def _extract_code(self, response: str) -> str:
        """Extract Python code from response."""
        import re
        
        # Try code block
        match = re.search(r'```python\s*(.*?)\s*```', response, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        # Try to find def transform
        if 'def transform' in response:
            start = response.find('def transform')
            return response[start:].strip()
        
        return response.strip()
    
    def get_terminal_nodes(self, workspace_id: str) -> List[MCTSNode]:
        """Get all terminal nodes with code."""
        trace = self._traces.get(workspace_id)
        if not trace:
            return []
        
        return [
            node for node in trace.nodes.values()
            if node.is_terminal and node.code_content
        ]
    
    def get_best_code(self, workspace_id: str) -> Optional[str]:
        """Get code from the best terminal node."""
        trace = self._traces.get(workspace_id)
        if not trace or not trace.best_leaf_id:
            return None
        
        node = trace.nodes.get(trace.best_leaf_id)
        return node.code_content if node else None

# ============================================================================
# SINGLETON
# ============================================================================

_mcts_service: Optional[MCTSService] = None

def get_mcts_service() -> MCTSService:
    global _mcts_service
    if _mcts_service is None:
        _mcts_service = MCTSService()
    return _mcts_service
