"""
Unified domain models for ARC-AGI solving.
Combines Pydantic models from both implementations.
"""
from typing import List, Dict, Optional, Any, Literal
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum
import uuid

# ============================================================================
# UTILITIES
# ============================================================================

def new_id() -> str:
    """Generate a new unique ID."""
    return uuid.uuid4().hex[:12]

# ============================================================================
# ARC TYPES
# ============================================================================

class ARCGrid(BaseModel):
    """A 2D grid of colors (0-9)."""
    width: int
    height: int
    cells: List[List[int]]
    
    @classmethod
    def from_list(cls, cells: List[List[int]]) -> "ARCGrid":
        if not cells:
            return cls(width=0, height=0, cells=[])
        return cls(width=len(cells[0]), height=len(cells), cells=cells)
    
    def to_list(self) -> List[List[int]]:
        return self.cells

class ARCPair(BaseModel):
    """An input-output training pair."""
    input: ARCGrid
    output: ARCGrid

class ARCTask(BaseModel):
    """A complete ARC task."""
    task_id: str
    train_pairs: List[ARCPair]
    test_inputs: List[ARCGrid]
    test_outputs: Optional[List[ARCGrid]] = None  # Ground truth if available
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    @property
    def num_train(self) -> int:
        return len(self.train_pairs)
    
    @property
    def num_test(self) -> int:
        return len(self.test_inputs)

# ============================================================================
# CANDIDATE TYPES
# ============================================================================

class CandidateType(str, Enum):
    TRANSDUCTION = "transduction"  # Direct grid prediction
    PROGRAM = "program"            # Python code
    RECURSIVE = "recursive"        # TRM-style recursive

class CandidateStatus(str, Enum):
    PENDING = "pending"
    TESTING = "testing"
    VERIFIED = "verified"
    PARTIAL = "partial"
    INVALID = "invalid"
    SELECTED = "selected"

class CandidateScore(BaseModel):
    """Scoring for a candidate solution."""
    train_pass_rate: float = 0.0
    examples_passed: int = 0
    examples_total: int = 0
    distance_metric: float = 1.0
    verified: bool = False

class CandidatePayload(BaseModel):
    """Payload containing the actual solution."""
    grid_outputs: Optional[List[ARCGrid]] = None
    program_code: Optional[str] = None

class CandidateSolution(BaseModel):
    """A candidate solution for an ARC task."""
    candidate_id: str = Field(default_factory=new_id)
    workspace_id: str
    type: CandidateType
    payload: CandidatePayload
    status: CandidateStatus = CandidateStatus.PENDING
    score: CandidateScore = Field(default_factory=CandidateScore)
    hypothesis_text: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: Dict[str, Any] = Field(default_factory=dict)

# ============================================================================
# MCTS TYPES
# ============================================================================

class MCTSNodeType(str, Enum):
    ROOT = "root"
    STRATEGY = "strategy"      # High-level approach
    TACTICAL = "tactical"      # Specific implementation
    TERMINAL = "terminal"      # Final code/solution

class MCTSNode(BaseModel):
    """A node in the MCTS search tree."""
    id: str = Field(default_factory=new_id)
    type: MCTSNodeType
    parent_id: Optional[str] = None
    children_ids: List[str] = Field(default_factory=list)
    
    # Content
    text_content: Optional[str] = None
    code_content: Optional[str] = None
    
    # Statistics
    visits: int = 0
    value_sum: float = 0.0
    prior_probability: float = 1.0
    
    # State
    is_expanded: bool = False
    is_terminal: bool = False
    depth: int = 0
    
    def uct_score(self, parent_visits: int, exploration_weight: float = 1.41) -> float:
        """Calculate UCT score for node selection."""
        import math
        if self.visits == 0:
            return float('inf')
        exploitation = self.value_sum / self.visits
        exploration = exploration_weight * math.sqrt(math.log(parent_visits) / self.visits)
        return exploitation + exploration
    
    @property
    def average_value(self) -> float:
        return self.value_sum / self.visits if self.visits > 0 else 0.0

class SearchTrace(BaseModel):
    """Complete MCTS search trace for a workspace."""
    workspace_id: str
    nodes: Dict[str, MCTSNode] = Field(default_factory=dict)
    root_id: str
    best_leaf_id: Optional[str] = None
    iterations: int = 0

# ============================================================================
# WORKSPACE TYPES
# ============================================================================

class WorkspaceStatus(str, Enum):
    INITIALIZED = "initialized"
    ANALYZING = "analyzing"
    SEARCHING = "searching"
    GENERATING = "generating"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"

class WorkspaceMetrics(BaseModel):
    """Metrics tracked for a workspace."""
    tokens_used: int = 0
    cost_usd: float = 0.0
    api_calls: int = 0
    candidates_generated: int = 0
    candidates_verified: int = 0
    iterations: int = 0
    duration_seconds: float = 0.0

class Workspace(BaseModel):
    """A solving workspace for a single ARC task."""
    workspace_id: str = Field(default_factory=new_id)
    task: ARCTask
    strategy: str = "default"
    status: WorkspaceStatus = WorkspaceStatus.INITIALIZED
    metrics: WorkspaceMetrics = Field(default_factory=WorkspaceMetrics)
    
    # Results
    best_candidate_ids: List[str] = Field(default_factory=list)
    predictions: List[List[List[List[int]]]] = Field(default_factory=list)  # k predictions per test
    prediction_confidences: List[List[float]] = Field(default_factory=list)  # confidence per prediction
    is_solved: bool = False
    
    # State
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    completed_at: Optional[str] = None

# ============================================================================
# VERIFICATION TYPES
# ============================================================================

class TrainResult(BaseModel):
    """Result for a single training example."""
    pair_index: int
    expected: ARCGrid
    produced: ARCGrid
    passed: bool
    distance: int
    distance_normalized: float
    diff_details: Optional[Dict[str, Any]] = None

class VerificationResult(BaseModel):
    """Result of verifying a candidate."""
    verification_id: str = Field(default_factory=new_id)
    candidate_id: str
    workspace_id: str
    train_results: List[TrainResult]
    all_passed: bool
    pass_rate: float
    average_distance: float
    error: Optional[str] = None
    execution_logs: List[str] = Field(default_factory=list)

# ============================================================================
# COT (CHAIN OF THOUGHT) TYPES
# ============================================================================

class HypothesisStatus(str, Enum):
    PROPOSED = "proposed"
    TESTING = "testing"
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    ABANDONED = "abandoned"

class Hypothesis(BaseModel):
    """A hypothesis about the transformation."""
    id: str = Field(default_factory=lambda: f"h_{new_id()[:6]}")
    text: str
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float = 0.5
    iteration: int = 0
    
    # Results
    code: Optional[str] = None
    examples_passed: int = 0
    examples_total: int = 0
    error_message: Optional[str] = None
    
    # Lineage
    parent_id: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

class Observation(BaseModel):
    """An observation about the task."""
    id: str = Field(default_factory=lambda: f"o_{new_id()[:6]}")
    text: str
    category: str = "general"
    confidence: float = 1.0
    source: str = "analysis"
    iteration: int = 0

class CriticFeedback(BaseModel):
    """Feedback from the critic model."""
    id: str = Field(default_factory=lambda: f"c_{new_id()[:6]}")
    iteration: int
    is_making_progress: bool
    is_stuck_in_loop: bool
    confidence_score: int  # 1-10
    current_assessment: str
    suggested_pivot: Optional[str] = None
    overlooked_aspects: List[str] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)
    raw_response: str = ""

class FailedAttempt(BaseModel):
    """Record of a failed attempt."""
    id: str = Field(default_factory=lambda: f"a_{new_id()[:6]}")
    hypothesis_id: str
    code: str
    error_type: str
    error_message: str
    examples_passed: int
    examples_total: int
    iteration: int
    diff_summary: Optional[str] = None

# ============================================================================
# API RESPONSE TYPES
# ============================================================================

class APIResponse(BaseModel):
    """Standard API response."""
    ok: bool = True
    error: Optional[str] = None
    data: Optional[Any] = None

class SolveResponse(BaseModel):
    """Response from solving a task."""
    workspace_id: str
    task_id: str
    solved: bool
    predictions: List[List[List[List[int]]]]  # k predictions per test
    prediction_confidences: List[List[float]] = Field(default_factory=list)  # confidence per prediction
    confidence: float  # legacy field: overall best score
    metrics: WorkspaceMetrics
    best_candidate_ids: List[str]
