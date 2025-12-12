"""
Structured Chain-of-Thought Log for tracking reasoning state.
Stores hypotheses, observations, failures, and critic feedback.
"""
import json
from datetime import datetime
from typing import List, Dict, Optional, Any
from dataclasses import asdict

from ..models import (
    Hypothesis, HypothesisStatus, Observation, 
    CriticFeedback, FailedAttempt, new_id
)

# ============================================================================
# COT LOG
# ============================================================================

class COTLog:
    """
    Structured Chain-of-Thought Log.
    
    Tracks the entire reasoning process for a single ARC task:
    - Hypotheses proposed and their outcomes
    - Observations accumulated
    - Failed attempts and their errors
    - Critic feedback and guidance
    """
    
    def __init__(self, workspace_id: str):
        self.workspace_id = workspace_id
        self.created_at = datetime.utcnow().isoformat()
        
        # Core tracking
        self.hypotheses: Dict[str, Hypothesis] = {}
        self.observations: Dict[str, Observation] = {}
        self.failed_attempts: List[FailedAttempt] = []
        self.critic_feedback: List[CriticFeedback] = []
        
        # State
        self.current_iteration: int = 0
        self.best_hypothesis_id: Optional[str] = None
        self.best_score: float = 0.0
        self.is_solved: bool = False
        self.solution_code: Optional[str] = None
        
        # Counters
        self._h_counter = 0
        self._o_counter = 0
        self._a_counter = 0
        self._c_counter = 0
    
    # =========================================================================
    # HYPOTHESIS MANAGEMENT
    # =========================================================================
    
    def add_hypothesis(
        self,
        text: str,
        confidence: float = 0.5,
        parent_id: Optional[str] = None
    ) -> Hypothesis:
        """Add a new hypothesis."""
        self._h_counter += 1
        h_id = f"h_{self._h_counter:03d}"
        
        h = Hypothesis(
            id=h_id,
            text=text,
            confidence=confidence,
            iteration=self.current_iteration,
            parent_id=parent_id,
        )
        self.hypotheses[h_id] = h
        return h
    
    def update_hypothesis(
        self,
        hypothesis_id: str,
        status: Optional[HypothesisStatus] = None,
        code: Optional[str] = None,
        examples_passed: Optional[int] = None,
        examples_total: Optional[int] = None,
        error: Optional[str] = None,
        confidence: Optional[float] = None,
    ):
        """Update an existing hypothesis."""
        if hypothesis_id not in self.hypotheses:
            return
        
        h = self.hypotheses[hypothesis_id]
        
        if status is not None:
            h.status = status
        if code is not None:
            h.code = code
        if examples_passed is not None:
            h.examples_passed = examples_passed
        if examples_total is not None:
            h.examples_total = examples_total
        if error is not None:
            h.error_message = error
        if confidence is not None:
            h.confidence = confidence
        
        # Update best if this is now the best
        if examples_passed is not None and examples_total is not None and examples_total > 0:
            score = examples_passed / examples_total
            if score > self.best_score:
                self.best_score = score
                self.best_hypothesis_id = hypothesis_id
            
            if examples_passed == examples_total:
                self.is_solved = True
                self.solution_code = code
    
    def get_hypothesis(self, hypothesis_id: str) -> Optional[Hypothesis]:
        return self.hypotheses.get(hypothesis_id)
    
    def get_active_hypotheses(self) -> List[Hypothesis]:
        """Get hypotheses that haven't failed or been abandoned."""
        return [
            h for h in self.hypotheses.values()
            if h.status not in [HypothesisStatus.FAILED, HypothesisStatus.ABANDONED]
        ]
    
    def get_failed_hypotheses(self) -> List[Hypothesis]:
        return [h for h in self.hypotheses.values() if h.status == HypothesisStatus.FAILED]
    
    # =========================================================================
    # OBSERVATION MANAGEMENT
    # =========================================================================
    
    def add_observation(
        self,
        text: str,
        category: str = "general",
        confidence: float = 1.0,
        source: str = "analysis"
    ) -> Observation:
        """Add a new observation (deduplicates)."""
        # Check for duplicates
        for o in self.observations.values():
            if o.text == text:
                return o
        
        self._o_counter += 1
        o_id = f"o_{self._o_counter:03d}"
        
        o = Observation(
            id=o_id,
            text=text,
            category=category,
            confidence=confidence,
            source=source,
            iteration=self.current_iteration,
        )
        self.observations[o_id] = o
        return o
    
    def get_observations_by_category(self, category: str) -> List[Observation]:
        return [o for o in self.observations.values() if o.category == category]
    
    # =========================================================================
    # FAILURE TRACKING
    # =========================================================================
    
    def add_failed_attempt(
        self,
        hypothesis_id: str,
        code: str,
        error_type: str,
        error_message: str,
        examples_passed: int,
        examples_total: int,
        diff_summary: Optional[str] = None,
    ) -> FailedAttempt:
        """Record a failed code attempt."""
        self._a_counter += 1
        
        attempt = FailedAttempt(
            id=f"a_{self._a_counter:03d}",
            hypothesis_id=hypothesis_id,
            code=code,
            error_type=error_type,
            error_message=error_message,
            examples_passed=examples_passed,
            examples_total=examples_total,
            iteration=self.current_iteration,
            diff_summary=diff_summary,
        )
        self.failed_attempts.append(attempt)
        return attempt
    
    def get_recent_failures(self, n: int = 3) -> List[FailedAttempt]:
        return self.failed_attempts[-n:]
    
    def get_unique_error_types(self) -> List[str]:
        return list(set(a.error_type for a in self.failed_attempts))
    
    # =========================================================================
    # CRITIC FEEDBACK
    # =========================================================================
    
    def add_critic_feedback(
        self,
        is_making_progress: bool,
        is_stuck_in_loop: bool,
        confidence_score: int,
        current_assessment: str,
        suggested_pivot: Optional[str],
        overlooked_aspects: List[str],
        next_steps: List[str],
        raw_response: str = "",
    ) -> CriticFeedback:
        """Add feedback from the critic."""
        self._c_counter += 1
        
        feedback = CriticFeedback(
            id=f"c_{self._c_counter:03d}",
            iteration=self.current_iteration,
            is_making_progress=is_making_progress,
            is_stuck_in_loop=is_stuck_in_loop,
            confidence_score=confidence_score,
            current_assessment=current_assessment,
            suggested_pivot=suggested_pivot,
            overlooked_aspects=overlooked_aspects,
            next_steps=next_steps,
            raw_response=raw_response,
        )
        self.critic_feedback.append(feedback)
        return feedback
    
    def get_latest_feedback(self) -> Optional[CriticFeedback]:
        return self.critic_feedback[-1] if self.critic_feedback else None
    
    def get_average_confidence(self) -> float:
        if not self.critic_feedback:
            return 5.0
        return sum(f.confidence_score for f in self.critic_feedback) / len(self.critic_feedback)
    
    # =========================================================================
    # CONTEXT GENERATION
    # =========================================================================
    
    def get_context_for_solver(self, max_chars: int = 8000) -> str:
        """Generate context string for the solver model."""
        lines = []
        
        # Key observations
        high_conf_obs = [o for o in self.observations.values() if o.confidence >= 0.8]
        if high_conf_obs:
            lines.append("## Established Facts")
            for o in high_conf_obs[:10]:
                lines.append(f"- {o.text}")
            lines.append("")
        
        # Failed hypotheses
        failed = self.get_failed_hypotheses()
        if failed:
            lines.append("## Already Tried (Failed)")
            for h in failed[-5:]:
                reason = h.error_message or "Incorrect output"
                lines.append(f"- {h.text[:80]} → {reason[:50]}")
            lines.append("")
        
        # Recent errors
        recent_fails = self.get_recent_failures(3)
        if recent_fails:
            lines.append("## Recent Errors")
            for a in recent_fails:
                lines.append(f"- {a.error_type}: {a.error_message[:80]}")
            lines.append("")
        
        # Latest critic guidance
        feedback = self.get_latest_feedback()
        if feedback:
            lines.append("## Guidance")
            lines.append(f"Assessment: {feedback.current_assessment}")
            if feedback.suggested_pivot:
                lines.append(f"Suggestion: {feedback.suggested_pivot}")
            if feedback.next_steps:
                lines.append("Next steps:")
                for step in feedback.next_steps[:3]:
                    lines.append(f"  - {step}")
            lines.append("")
        
        # Best progress
        if self.best_hypothesis_id and self.best_score > 0:
            best = self.hypotheses[self.best_hypothesis_id]
            lines.append(f"## Best Progress: {self.best_score*100:.0f}% correct")
            lines.append(f"Approach: {best.text[:100]}")
            lines.append("")
        
        context = "\n".join(lines)
        
        if len(context) > max_chars:
            context = context[:max_chars] + "\n... (truncated)"
        
        return context
    
    def get_context_for_critic(self) -> str:
        """Generate full context for critic analysis."""
        lines = [
            f"# Reasoning Log for Workspace {self.workspace_id}",
            f"Iteration: {self.current_iteration}",
            f"Solved: {self.is_solved}",
            f"Best Score: {self.best_score*100:.0f}%",
            ""
        ]
        
        # All hypotheses
        lines.append("## Hypotheses")
        for h in self.hypotheses.values():
            score = f"{h.examples_passed}/{h.examples_total}" if h.examples_total > 0 else "N/A"
            lines.append(f"- [{h.status.value.upper()}] {h.text}")
            lines.append(f"  Score: {score}")
            if h.error_message:
                lines.append(f"  Error: {h.error_message[:100]}")
        lines.append("")
        
        # Observations
        lines.append("## Observations")
        for o in self.observations.values():
            lines.append(f"- [{o.category}] {o.text}")
        lines.append("")
        
        # Failure patterns
        if self.failed_attempts:
            error_counts = {}
            for a in self.failed_attempts:
                error_counts[a.error_type] = error_counts.get(a.error_type, 0) + 1
            lines.append("## Failure Patterns")
            for error_type, count in error_counts.items():
                lines.append(f"- {error_type}: {count}x")
        
        return "\n".join(lines)
    
    # =========================================================================
    # SERIALIZATION
    # =========================================================================
    
    def to_dict(self) -> Dict:
        return {
            "workspace_id": self.workspace_id,
            "created_at": self.created_at,
            "current_iteration": self.current_iteration,
            "is_solved": self.is_solved,
            "best_score": self.best_score,
            "best_hypothesis_id": self.best_hypothesis_id,
            "solution_code": self.solution_code,
            "hypotheses": {k: v.model_dump() for k, v in self.hypotheses.items()},
            "observations": {k: v.model_dump() for k, v in self.observations.items()},
            "failed_attempts": [a.model_dump() for a in self.failed_attempts],
            "critic_feedback": [f.model_dump() for f in self.critic_feedback],
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)
    
    # =========================================================================
    # ITERATION
    # =========================================================================
    
    def next_iteration(self):
        self.current_iteration += 1
    
    def get_stats(self) -> Dict:
        return {
            "iterations": self.current_iteration,
            "hypotheses_total": len(self.hypotheses),
            "hypotheses_passed": len([h for h in self.hypotheses.values() if h.status == HypothesisStatus.PASSED]),
            "hypotheses_failed": len([h for h in self.hypotheses.values() if h.status == HypothesisStatus.FAILED]),
            "observations": len(self.observations),
            "failed_attempts": len(self.failed_attempts),
            "critic_reviews": len(self.critic_feedback),
            "best_score": self.best_score,
            "is_solved": self.is_solved,
        }
