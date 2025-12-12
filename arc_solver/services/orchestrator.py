"""
Main orchestrator that coordinates the solving process.
Combines MCTS exploration, hypothesis generation, verification, and critic feedback.
"""
import asyncio
import time
from typing import List, Dict, Optional, Any, Tuple
from dataclasses import dataclass
from loguru import logger

from ..config import load_config, get_strategy, StrategyProfile
from ..models import (
    ARCTask, ARCGrid, ARCPair, Workspace, WorkspaceStatus, WorkspaceMetrics,
    CandidateSolution, CandidateType, CandidatePayload, CandidateStatus, CandidateScore,
    HypothesisStatus, new_id
)
from ..tools.grid_analyzer import GridAnalyzer, get_analyzer
from ..tools.code_executor import CodeExecutor, get_executor, ValidationResult
from ..memory.cot_log import COTLog
from .llm_client import LLMClient, Message, get_llm_client
from .mcts_service import MCTSService, get_mcts_service

# ============================================================================
# PROMPTS
# ============================================================================

SOLVER_SYSTEM_PROMPT = """You are an expert at solving ARC-AGI (Abstraction and Reasoning Corpus) puzzles.

ARC is about ABSTRACTION and REASONING, not memorization. You must:
1. Find the ABSTRACT RULE that generalizes across all examples
2. Think about RELATIONSHIPS and PATTERNS, not specific pixel values
3. Use RELATIVE positions and transformations, not absolute coordinates
4. Learn from 2-3 examples only - your rule must generalize

Common ARC patterns to consider:
- **Gravity/Physics**: Objects falling, stacking, or settling
- **Flood fill**: Spreading colors based on connectivity or boundaries
- **Symmetry**: Reflections, rotations, or creating symmetric patterns
- **Object detection**: Identifying and manipulating distinct objects or shapes
- **Pattern completion**: Extending or completing partial patterns
- **Geometric transformations**: Scaling, rotation, translation, mirroring
- **Color rules**: Mapping, replacing, or combining colors based on context
- **Spatial relationships**: Alignment, proximity, containment, adjacency
- **Grid operations**: Cropping, tiling, overlaying, or extracting sub-grids

Your task is to:
1. Analyze the input-output training pairs
2. Identify the ABSTRACT transformation pattern/rule
3. Implement the transformation as Python code

Rules for your code:
- Function MUST be named `transform`
- Input: numpy array `input_grid` (2D array of integers 0-9)
- Output: transformed grid as list of lists
- You may use: numpy, itertools, functools, collections, copy, math

Example structure:
```python
import numpy as np

def transform(input_grid):
    grid = np.array(input_grid)
    # Your transformation logic
    return result.tolist()
```"""

HYPOTHESIS_PROMPT = """## Task
Analyze these ARC training examples and propose a transformation hypothesis.

## Training Examples
{examples}

## Grid Analysis
{analysis}

## Previous Context
{context}

## Instructions
1. Look for the ABSTRACT RULE that generalizes across all examples
2. Think about RELATIONSHIPS between objects, not individual pixels
3. Consider spatial transformations and patterns
4. Propose ONE clear hypothesis about the transformation
5. Implement it as Python code that will work on ANY input following this pattern

Key reasoning guidelines:
- What is the PATTERN that connects all input-output pairs?
- What RELATIONSHIPS or SPATIAL PROPERTIES are preserved or transformed?
- Consider these common operations:
  * Detecting and manipulating objects (connected components)
  * Applying geometric transformations (rotate, flip, scale, translate)
  * Color mapping or replacement based on rules
  * Flood fill or spreading patterns
  * Cropping, tiling, or grid operations
  * Pattern matching and completion
  * Applying physics-like rules (gravity, stacking)

Respond in this format:
HYPOTHESIS: [Your hypothesis in one sentence]

CODE:
```python
import numpy as np

def transform(input_grid):
    grid = np.array(input_grid)
    # Implementation
    return result.tolist()
```"""

REVISION_PROMPT = """## Task
Fix the code that failed on some examples.

## Hypothesis
{hypothesis}

## Current Code
```python
{code}
```

## Error
{error}

## Failed Example Details
Expected output:
{expected}

Actual output:
{actual}

## Instructions
Analyze why the code failed and provide a corrected version.
Return ONLY the corrected Python code:

```python
import numpy as np

def transform(input_grid):
    # Fixed implementation
    return result.tolist()
```"""

CRITIC_SYSTEM_PROMPT = """You are a reasoning analyst for ARC-AGI puzzle solving.

Your role is to:
1. Assess if the solver is making progress toward finding the ABSTRACT RULE
2. Detect if it's stuck in a loop or overfitting to specific examples
3. Suggest pivots or new approaches based on common ARC patterns
4. Identify overlooked aspects (spatial relationships, transformations, patterns)

Key things to check:
- Is the hypothesis too SPECIFIC (memorizing examples rather than finding the rule)?
- Does it handle EDGE CASES and variations?
- Are there overlooked PATTERNS (symmetry, object relationships, color rules)?
- Should we try a different approach type (geometric, object-based, color-based, etc.)?

Common failure patterns to detect:
- **Overfitting**: Hypothesis works for training but won't generalize
- **Wrong abstraction level**: Too pixel-focused instead of pattern-focused
- **Missed transformations**: Not considering rotation, reflection, scaling
- **Ignored relationships**: Not seeing spatial or logical connections
- **Wrong operation category**: Trying color rules when it's geometric, etc.

Be specific, constructive, and actionable."""

CRITIC_PROMPT = """## Task Description
Solving ARC task {task_id} with {num_train} training examples.

## Reasoning Log
{log}

## Current State
- Iteration: {iteration}
- Best Score: {best_score}%
- Hypotheses Tried: {num_hypotheses}
- Failed Attempts: {num_failures}

## Instructions
Analyze the reasoning process and provide feedback.

Respond with JSON:
{{
    "is_making_progress": true/false,
    "is_stuck_in_loop": true/false,
    "confidence_score": 1-10,
    "current_assessment": "Brief assessment of current state",
    "suggested_pivot": "New approach to try, or null",
    "overlooked_aspects": ["Aspect 1", "Aspect 2"],
    "recommended_next_steps": ["Step 1", "Step 2", "Step 3"]
}}"""

# ============================================================================
# ORCHESTRATOR
# ============================================================================

class Orchestrator:
    """
    Main orchestrator that coordinates the ARC solving process.
    
    Pipeline:
    1. Analyze task (grid analysis, pattern detection)
    2. Generate hypotheses (via MCTS or direct generation)
    3. Generate code for each hypothesis
    4. Validate against training examples
    5. Revise failed code with feedback
    6. Run critic for meta-reasoning
    7. Repeat until solved or budget exhausted
    """
    
    def __init__(self):
        self._workspaces: Dict[str, Workspace] = {}
        self._cot_logs: Dict[str, COTLog] = {}
        self._candidates: Dict[str, CandidateSolution] = {}
        
        self._analyzer: Optional[GridAnalyzer] = None
        self._executor: Optional[CodeExecutor] = None
        self._client: Optional[LLMClient] = None
        self._mcts: Optional[MCTSService] = None
    
    async def _init_services(self):
        """Initialize services lazily."""
        if self._analyzer is None:
            self._analyzer = get_analyzer()
        if self._executor is None:
            self._executor = get_executor()
        if self._client is None:
            self._client = await get_llm_client()
        if self._mcts is None:
            self._mcts = get_mcts_service()
    
    def create_workspace(self, task: ARCTask, strategy: str = None) -> Workspace:
        """Create a new solving workspace."""
        ws = Workspace(
            task=task,
            strategy=strategy or load_config().default_strategy
        )
        self._workspaces[ws.workspace_id] = ws
        self._cot_logs[ws.workspace_id] = COTLog(ws.workspace_id)
        return ws
    
    def get_workspace(self, workspace_id: str) -> Optional[Workspace]:
        return self._workspaces.get(workspace_id)
    
    def get_cot_log(self, workspace_id: str) -> Optional[COTLog]:
        return self._cot_logs.get(workspace_id)
    
    async def solve(self, workspace_id: str) -> Workspace:
        """
        Main solving loop.
        """
        await self._init_services()
        
        ws = self._workspaces.get(workspace_id)
        if not ws:
            raise ValueError(f"Workspace {workspace_id} not found")
        
        cot = self._cot_logs[workspace_id]
        strategy = get_strategy(ws.strategy)
        cfg = load_config()
        
        start_time = time.time()
        ws.status = WorkspaceStatus.ANALYZING
        
        logger.info(f"Starting solve for task {ws.task.task_id}")
        
        try:
            # 1. Analyze task
            analysis = await self._analyze_task(ws, cot)
            
            # 2. Main solving loop
            ws.status = WorkspaceStatus.SEARCHING
            
            for iteration in range(strategy.solver.max_iterations):
                cot.next_iteration()
                logger.info(f"Iteration {cot.current_iteration}")
                
                # Check if solved
                if cot.is_solved:
                    logger.info("Task solved!")
                    break
                
                # Check budget
                if ws.metrics.cost_usd >= strategy.cost_budget_usd:
                    logger.warning("Cost budget exhausted")
                    break
                
                # Generate hypotheses
                ws.status = WorkspaceStatus.GENERATING
                hypotheses = await self._generate_hypotheses(
                    ws, cot, analysis, 
                    num_hypotheses=strategy.solver.max_hypotheses_per_iteration
                )
                
                # BUG FIX 4: Process hypotheses in parallel if enabled
                ws.status = WorkspaceStatus.VERIFYING
                if strategy.solver.parallel_hypotheses:
                    logger.info(f"Processing {len(hypotheses)} hypotheses in parallel")
                    tasks = [
                        self._process_hypothesis(ws, cot, h_id, strategy)
                        for h_id in hypotheses
                    ]
                    await asyncio.gather(*tasks)
                else:
                    # Sequential processing
                    for h_id in hypotheses:
                        if cot.is_solved:
                            break

                        await self._process_hypothesis(ws, cot, h_id, strategy)
                
                # Critic review every 2 iterations
                if cot.current_iteration % 2 == 0 and not cot.is_solved:
                    await self._run_critic(ws, cot)
                
                # Update metrics
                ws.metrics.iterations = cot.current_iteration
                ws.metrics.cost_usd = self._client.usage.total_cost
                ws.metrics.tokens_used = self._client.usage.input_tokens + self._client.usage.output_tokens
                ws.metrics.api_calls = self._client.usage.api_calls
            
            # 3. Finalize
            ws.metrics.duration_seconds = time.time() - start_time
            
            if cot.is_solved:
                ws.is_solved = True
                ws.status = WorkspaceStatus.COMPLETED

                # Generate predictions for test inputs (k=2 per test)
                ws.predictions, ws.prediction_confidences = await self._generate_predictions(ws, cot)

                if cot.best_hypothesis_id:
                    ws.best_candidate_ids = [cot.best_hypothesis_id]
            else:
                ws.status = WorkspaceStatus.COMPLETED

                # Best effort predictions
                if cot.best_hypothesis_id and cot.best_score > 0:
                    ws.predictions, ws.prediction_confidences = await self._generate_predictions(ws, cot)
                else:
                    # Fallback to input unchanged (k=2 predictions per test)
                    ws.predictions = [[inp.cells, inp.cells] for inp in ws.task.test_inputs]
                    ws.prediction_confidences = [[0.0, 0.0] for _ in ws.task.test_inputs]
            
            logger.info(f"Solve completed: solved={ws.is_solved}, score={cot.best_score*100:.0f}%")
            
        except Exception as e:
            logger.error(f"Solve failed: {e}")
            ws.status = WorkspaceStatus.FAILED
            ws.metrics.duration_seconds = time.time() - start_time
            raise
        
        return ws
    
    async def _analyze_task(self, ws: Workspace, cot: COTLog) -> str:
        """Analyze the task and add observations to COT."""
        lines = []
        
        for i, pair in enumerate(ws.task.train_pairs):
            in_analysis = self._analyzer.analyze(pair.input)
            out_analysis = self._analyzer.analyze(pair.output)
            transform = self._analyzer.analyze_transformation(pair)
            
            lines.append(f"### Example {i+1}")
            lines.append(f"Input: {in_analysis.height}x{in_analysis.width}, colors={in_analysis.colors_present}")
            lines.append(f"Output: {out_analysis.height}x{out_analysis.width}, colors={out_analysis.colors_present}")
            
            if transform['transformations_detected']:
                lines.append(f"Detected: {', '.join(transform['transformations_detected'])}")
                for t in transform['transformations_detected']:
                    cot.add_observation(f"Example {i+1} shows {t}", category="transformation")
            
            # Add dimensional observations
            if in_analysis.height != out_analysis.height or in_analysis.width != out_analysis.width:
                cot.add_observation(
                    f"Dimensions change: {in_analysis.height}x{in_analysis.width} → {out_analysis.height}x{out_analysis.width}",
                    category="dimension"
                )
            else:
                cot.add_observation("Dimensions preserved", category="dimension")
            
            # Symmetry observations
            if in_analysis.has_horizontal_symmetry:
                cot.add_observation(f"Example {i+1} input has horizontal symmetry", category="symmetry")
            if out_analysis.has_horizontal_symmetry:
                cot.add_observation(f"Example {i+1} output has horizontal symmetry", category="symmetry")
            
            lines.append("")
        
        return "\n".join(lines)
    
    async def _generate_hypotheses(
        self,
        ws: Workspace,
        cot: COTLog,
        analysis: str,
        num_hypotheses: int = 3
    ) -> List[str]:
        """Generate hypotheses using MCTS exploration and LLM."""
        cfg = load_config()
        hypothesis_ids = []

        # BUG FIX 1: Use MCTS to explore the search space
        logger.info("Running MCTS exploration to generate hypotheses")
        try:
            # Run MCTS iterations to explore transformation patterns
            mcts_iterations = min(20, num_hypotheses * 5)  # Scale iterations with hypothesis count
            trace = await self._mcts.run_iterations(
                workspace_id=ws.workspace_id,
                analysis_context=analysis,
                num_iterations=mcts_iterations,
                train_pairs=ws.task.train_pairs,  # Pass training pairs for REAL code validation
            )
            terminal_nodes = self._mcts.get_terminal_nodes(ws.workspace_id)

            # Extract hypotheses from terminal nodes
            logger.info(f"MCTS found {len(terminal_nodes)} terminal nodes")
            for node in terminal_nodes[:num_hypotheses]:
                if node.text_content and node.code_content:
                    h = cot.add_hypothesis(node.text_content)
                    h.code = node.code_content
                    hypothesis_ids.append(h.id)
                    ws.metrics.candidates_generated += 1
        except Exception as e:
            logger.warning(f"MCTS exploration failed: {e}, falling back to direct generation")

        # If MCTS didn't produce enough hypotheses, supplement with direct LLM generation
        remaining = num_hypotheses - len(hypothesis_ids)
        if remaining > 0:
            logger.info(f"Generating {remaining} additional hypotheses via direct LLM")

            # Format examples
            examples_text = self._format_examples(ws.task.train_pairs)
            context = cot.get_context_for_solver()

            # Diversity hints for different approaches
            diversity_hints = [
                "Try a pattern-matching approach: Look for repeating patterns, templates, or matching shapes that appear across examples.",
                "Try a geometric transformation approach: Consider rotations, reflections, translations, scaling, or other spatial operations.",
                "Try a color-based approach: Focus on color mappings, replacements, spreading, or rules based on color relationships.",
                "Try an object manipulation approach: Identify distinct objects (connected components) and apply operations like moving, copying, or transforming them.",
                "Try a rule-based approach: Look for logical rules, conditions, or step-by-step procedures that transform the input systematically."
            ]

            # Generate hypotheses
            prompts = []
            for i in range(remaining):
                # Add diversity hint based on index
                diversity_hint = diversity_hints[i % len(diversity_hints)]
                prompt_with_hint = HYPOTHESIS_PROMPT.format(
                    examples=examples_text,
                    analysis=analysis,
                    context=context
                ) + f"\n\n## Approach Guidance\n{diversity_hint}"

                prompts.append([
                    Message(role="system", content=SOLVER_SYSTEM_PROMPT),
                    Message(role="user", content=prompt_with_hint)
                ])

            # Parallel generation
            responses = await self._client.complete_parallel(prompts, cfg.models.reasoner)

            for resp in responses:
                if isinstance(resp, Exception):
                    logger.error(f"Hypothesis generation failed: {resp}")
                    continue

                # Parse response
                hypothesis_text, code = self._parse_hypothesis_response(resp.content)

                if hypothesis_text and code:
                    h = cot.add_hypothesis(hypothesis_text)
                    h.code = code
                    hypothesis_ids.append(h.id)
                    ws.metrics.candidates_generated += 1

        return hypothesis_ids
    
    async def _process_hypothesis(
        self,
        ws: Workspace,
        cot: COTLog,
        hypothesis_id: str,
        strategy: StrategyProfile
    ):
        """Process a single hypothesis: validate and revise."""
        h = cot.get_hypothesis(hypothesis_id)
        if not h or not h.code:
            return
        
        cot.update_hypothesis(hypothesis_id, status=HypothesisStatus.TESTING)
        
        # Validate
        result = self._executor.validate_against_examples(h.code, ws.task.train_pairs)
        ws.metrics.candidates_verified += 1
        
        h.examples_passed = result.num_passed
        h.examples_total = result.num_total
        
        if result.all_passed:
            cot.update_hypothesis(
                hypothesis_id,
                status=HypothesisStatus.PASSED,
                examples_passed=result.num_passed,
                examples_total=result.num_total
            )
            return
        
        # Revision loop for partial success
        if result.num_passed > 0:
            cot.update_hypothesis(hypothesis_id, status=HypothesisStatus.PARTIAL)

            # BUG FIX 3: Track previous passed count to detect no progress
            prev_passed = result.num_passed

            for attempt in range(strategy.solver.max_revision_attempts):
                revised_code = await self._revise_code(ws, cot, h, result)

                if not revised_code:
                    break

                h.code = revised_code
                result = self._executor.validate_against_examples(revised_code, ws.task.train_pairs)
                ws.metrics.candidates_verified += 1

                if result.all_passed:
                    cot.update_hypothesis(
                        hypothesis_id,
                        status=HypothesisStatus.PASSED,
                        code=revised_code,
                        examples_passed=result.num_passed,
                        examples_total=result.num_total
                    )
                    return

                # Check for progress
                if result.num_passed > prev_passed:
                    # Made progress, update tracking
                    prev_passed = result.num_passed
                    h.examples_passed = result.num_passed
                elif result.num_passed == prev_passed:
                    # No improvement, stop revising
                    logger.info(f"Revision attempt {attempt+1} made no progress (still {result.num_passed}/{result.num_total}), stopping early")
                    break
                else:
                    # Got worse, also stop
                    logger.info(f"Revision attempt {attempt+1} regressed ({result.num_passed} < {prev_passed}), stopping early")
                    break
        
        # Failed
        cot.update_hypothesis(
            hypothesis_id,
            status=HypothesisStatus.FAILED,
            examples_passed=result.num_passed,
            examples_total=result.num_total,
            error=result.error_summary
        )
        
        # Record failure
        cot.add_failed_attempt(
            hypothesis_id=hypothesis_id,
            code=h.code,
            error_type="validation",
            error_message=result.error_summary or "Did not pass all examples",
            examples_passed=result.num_passed,
            examples_total=result.num_total
        )
    
    async def _revise_code(
        self,
        ws: Workspace,
        cot: COTLog,
        hypothesis,
        result: ValidationResult
    ) -> Optional[str]:
        """Revise code based on failure."""
        cfg = load_config()
        
        # Find first failed example
        failed = None
        for r in result.results:
            if not r.get('passed'):
                failed = r
                break
        
        if not failed:
            return None
        
        # Format error info
        if 'error' in failed:
            error = f"{failed.get('error_type', 'Error')}: {failed['error']}"
            expected = "N/A (code error)"
            actual = "N/A (code error)"
        else:
            error = failed.get('diff', {}).get('summary', 'Output mismatch')
            expected = self._format_grid(failed.get('expected', []))
            actual = self._format_grid(failed.get('actual', []))
        
        prompt = REVISION_PROMPT.format(
            hypothesis=hypothesis.text,
            code=hypothesis.code,
            error=error,
            expected=expected,
            actual=actual
        )
        
        response = await self._client.complete(
            [
                Message(role="system", content=SOLVER_SYSTEM_PROMPT),
                Message(role="user", content=prompt)
            ],
            cfg.models.solver
        )
        
        return self._extract_code(response.content)
    
    async def _run_critic(self, ws: Workspace, cot: COTLog):
        """Run critic analysis."""
        cfg = load_config()
        strategy = get_strategy(ws.strategy)

        prompt = CRITIC_PROMPT.format(
            task_id=ws.task.task_id,
            num_train=ws.task.num_train,
            log=cot.get_context_for_critic(),
            iteration=cot.current_iteration,
            best_score=cot.best_score * 100,
            num_hypotheses=len(cot.hypotheses),
            num_failures=len(cot.failed_attempts)
        )

        try:
            response = await self._client.complete(
                [
                    Message(role="system", content=CRITIC_SYSTEM_PROMPT),
                    Message(role="user", content=prompt)
                ],
                cfg.models.critic
            )

            feedback = self._parse_critic_response(response.content)
            if feedback:
                cot.add_critic_feedback(**feedback, raw_response=response.content)
                logger.info(f"Critic: progress={feedback['is_making_progress']}, stuck={feedback['is_stuck_in_loop']}, confidence={feedback['confidence_score']}")

                # BUG FIX 2: Act on critic feedback
                if feedback['is_stuck_in_loop']:
                    logger.warning("Critic detected stuck in loop - forcing strategy pivot")
                    # Reset MCTS tree to force new exploration
                    self._mcts.reset_search(ws.workspace_id)
                    logger.info("Reset MCTS tree to enable new strategy exploration")
                    # Add observation to force new exploration direction
                    cot.add_observation(
                        "Critic detected repetitive patterns - need to explore alternative transformation approaches",
                        category="meta-reasoning"
                    )
                    # Increase exploration in next iteration by adding pivot suggestion
                    if feedback.get('suggested_pivot'):
                        logger.info(f"Applying suggested pivot: {feedback['suggested_pivot']}")
                        cot.add_observation(
                            f"Pivot suggestion: {feedback['suggested_pivot']}",
                            category="strategy"
                        )

                # Add overlooked aspects as observations
                for aspect in feedback.get('overlooked_aspects', []):
                    cot.add_observation(f"Overlooked: {aspect}", category="critic-insight")

        except Exception as e:
            logger.error(f"Critic failed: {e}")
    
    async def _generate_predictions(self, ws: Workspace, cot: COTLog) -> Tuple[List[List[List[List[int]]]], List[List[float]]]:
        """
        Generate k=2 predictions per test input with confidence scores.
        Returns: (predictions, confidences) where:
            - predictions: List[test][k][height][width]
            - confidences: List[test][k]
        """
        # Get top k=2 hypotheses by score
        passed_hypotheses = [
            h for h in cot.hypotheses.values()
            if h.status == HypothesisStatus.PASSED and h.code
        ]

        if not passed_hypotheses:
            # Fallback to best effort
            if cot.best_hypothesis_id:
                h = cot.get_hypothesis(cot.best_hypothesis_id)
                passed_hypotheses = [h] if h and h.code else []

        # Sort by score (examples_passed / examples_total)
        passed_hypotheses.sort(
            key=lambda h: (h.examples_passed / max(h.examples_total, 1), -len(h.code or "")),
            reverse=True
        )

        # Take top 2
        top_k_hypotheses = passed_hypotheses[:2]

        if not top_k_hypotheses:
            # Ultimate fallback: return input unchanged
            predictions = [[[inp.cells] for inp in ws.task.test_inputs]]
            confidences = [[[0.0] for _ in ws.task.test_inputs]]
            return predictions, confidences

        # Generate predictions from each hypothesis
        all_test_predictions = []
        all_test_confidences = []

        for test_input in ws.task.test_inputs:
            test_preds = []
            test_confs = []

            for hypothesis in top_k_hypotheses:
                result = self._executor.execute(hypothesis.code, test_input.cells)

                if result.success and result.output:
                    pred = result.output
                    # Calculate confidence
                    conf = self._calculate_confidence(hypothesis, pred, ws)
                else:
                    pred = test_input.cells
                    conf = 0.0

                test_preds.append(pred)
                test_confs.append(conf)

            # Ensemble if we have multiple predictions
            if len(test_preds) > 1:
                ensemble_pred = self._ensemble_predictions(test_preds)
                ensemble_conf = max(test_confs)  # Use highest confidence

                # Verify consistency
                if self._check_format_heuristics(ws, [ensemble_pred]):
                    test_preds.insert(0, ensemble_pred)
                    test_confs.insert(0, ensemble_conf)

            # Ensure we have exactly 2 predictions (pad if needed)
            while len(test_preds) < 2:
                test_preds.append(test_input.cells)
                test_confs.append(0.0)

            # Take top 2 by confidence
            sorted_pairs = sorted(zip(test_preds, test_confs), key=lambda x: x[1], reverse=True)
            test_preds = [p[0] for p in sorted_pairs[:2]]
            test_confs = [p[1] for p in sorted_pairs[:2]]

            all_test_predictions.append(test_preds)
            all_test_confidences.append(test_confs)

        return all_test_predictions, all_test_confidences

    def _ensemble_predictions(self, predictions: List[List[List[int]]]) -> List[List[int]]:
        """Cell-by-cell majority vote across predictions."""
        if len(predictions) <= 1:
            return predictions[0] if predictions else []

        # Find common dimensions (use the most common dimensions)
        heights = [len(p) for p in predictions if p]
        widths = [len(p[0]) for p in predictions if p and p[0]]

        if not heights or not widths:
            return predictions[0] if predictions else []

        from collections import Counter
        height = Counter(heights).most_common(1)[0][0]
        width = Counter(widths).most_common(1)[0][0]

        # Majority vote per cell
        result = []
        for i in range(height):
            row = []
            for j in range(width):
                votes = [p[i][j] for p in predictions if i < len(p) and j < len(p[i])]
                if votes:
                    most_common = Counter(votes).most_common(1)[0][0]
                    row.append(most_common)
                else:
                    row.append(0)
            result.append(row)

        return result

    def _check_format_heuristics(self, ws: Workspace, predictions: List[List[List[int]]]) -> bool:
        """
        Check if predictions match surface-level format patterns from training.
        NOTE: This does NOT verify correctness - only checks heuristics like:
        - Square output if training outputs are square
        - Color preservation if training preserves colors
        - Dimension ratios if training has consistent ratios
        This is a quick sanity check, NOT actual solution verification.
        """
        if not predictions or not ws.task.train_pairs:
            return True

        train_pairs = ws.task.train_pairs

        # Check 1: If all training outputs are square, check predictions are square
        all_square = all(
            len(pair.output.cells) == len(pair.output.cells[0]) if pair.output.cells and pair.output.cells[0] else False
            for pair in train_pairs
        )

        if all_square:
            for pred in predictions:
                if pred and pred[0] and len(pred) != len(pred[0]):
                    return False

        # Check 2: If all outputs have same colors as inputs, enforce this
        all_preserve_colors = True
        for pair in train_pairs:
            input_colors = set()
            for row in pair.input.cells:
                input_colors.update(row)
            output_colors = set()
            for row in pair.output.cells:
                output_colors.update(row)
            if output_colors - input_colors:
                all_preserve_colors = False
                break

        if all_preserve_colors:
            input_colors = set()
            for inp in ws.task.test_inputs:
                for row in inp.cells:
                    input_colors.update(row)

            for pred in predictions:
                pred_colors = set()
                for row in pred:
                    pred_colors.update(row)
                if pred_colors - input_colors:
                    return False

        # Check 3: If output dimensions follow a pattern, check predictions follow it
        dim_ratios = []
        for pair in train_pairs:
            in_h, in_w = len(pair.input.cells), len(pair.input.cells[0]) if pair.input.cells else 0
            out_h, out_w = len(pair.output.cells), len(pair.output.cells[0]) if pair.output.cells else 0
            if in_h > 0 and in_w > 0:
                dim_ratios.append((out_h / in_h, out_w / in_w))

        if dim_ratios and len(set(dim_ratios)) == 1:
            # All have same ratio
            expected_ratio = dim_ratios[0]
            for i, pred in enumerate(predictions):
                if i < len(ws.task.test_inputs):
                    test_input = ws.task.test_inputs[i]
                    in_h, in_w = len(test_input.cells), len(test_input.cells[0]) if test_input.cells else 0
                    pred_h, pred_w = len(pred), len(pred[0]) if pred else 0
                    if in_h > 0 and in_w > 0:
                        actual_ratio = (pred_h / in_h, pred_w / in_w)
                        if abs(actual_ratio[0] - expected_ratio[0]) > 0.01 or abs(actual_ratio[1] - expected_ratio[1]) > 0.01:
                            return False

        return True

    def _calculate_confidence(self, hypothesis, prediction: List[List[int]], ws: Workspace) -> float:
        """
        Calculate confidence score for a prediction.
        Confidence = training pass rate (proportion of examples passed).
        No arbitrary penalties - code length has no bearing on correctness.
        """
        if not hypothesis or hypothesis.examples_total == 0:
            return 0.0

        # Confidence = actual pass rate on training examples
        # This is the only meaningful metric - did the code work or not?
        confidence = hypothesis.examples_passed / hypothesis.examples_total

        return min(1.0, confidence)
    
    # =========================================================================
    # HELPERS
    # =========================================================================
    
    def _format_examples(self, pairs: List[ARCPair]) -> str:
        lines = []
        for i, pair in enumerate(pairs):
            lines.append(f"Example {i+1}:")
            lines.append(f"Input:\n{self._format_grid(pair.input.cells)}")
            lines.append(f"Output:\n{self._format_grid(pair.output.cells)}")
            lines.append("")
        return "\n".join(lines)
    
    def _format_grid(self, cells: List[List[int]]) -> str:
        if not cells:
            return "[]"
        return "\n".join(" ".join(str(c) for c in row) for row in cells)
    
    def _parse_hypothesis_response(self, response: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse hypothesis and code from response."""
        import re
        
        # Extract hypothesis
        hypothesis = None
        h_match = re.search(r'HYPOTHESIS:\s*(.+?)(?=CODE:|```|$)', response, re.DOTALL | re.IGNORECASE)
        if h_match:
            hypothesis = h_match.group(1).strip()
        
        # Extract code
        code = self._extract_code(response)
        
        return hypothesis, code
    
    def _extract_code(self, response: str) -> Optional[str]:
        import re
        
        # Try code block
        match = re.search(r'```python\s*(.*?)\s*```', response, re.DOTALL)
        if match:
            return match.group(1).strip()
        
        # Try plain code block
        match = re.search(r'```\s*(.*?)\s*```', response, re.DOTALL)
        if match:
            code = match.group(1).strip()
            if 'def transform' in code:
                return code
        
        # Try to find def transform directly
        if 'def transform' in response:
            start = response.find('def transform')
            return response[start:].strip()
        
        return None
    
    def _parse_critic_response(self, response: str) -> Optional[Dict]:
        import json
        import re
        
        # Try to find JSON
        match = re.search(r'\{.*\}', response, re.DOTALL)
        if match:
            try:
                data = json.loads(match.group())
                return {
                    "is_making_progress": data.get("is_making_progress", False),
                    "is_stuck_in_loop": data.get("is_stuck_in_loop", False),
                    "confidence_score": data.get("confidence_score", 5),
                    "current_assessment": data.get("current_assessment", ""),
                    "suggested_pivot": data.get("suggested_pivot"),
                    "overlooked_aspects": data.get("overlooked_aspects", []),
                    "next_steps": data.get("recommended_next_steps", [])
                }
            except json.JSONDecodeError:
                pass
        
        return None

# ============================================================================
# SINGLETON
# ============================================================================

_orchestrator: Optional[Orchestrator] = None

def get_orchestrator() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator()
    return _orchestrator
