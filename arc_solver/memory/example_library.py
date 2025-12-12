"""
Few-shot example library for ARC solver.
Stores solved tasks and retrieves similar ones based on grid features.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import numpy as np
import json
from pathlib import Path

from ..models import ARCTask, ARCGrid, ARCPair
from ..tools.grid_analyzer import GridAnalyzer, GridAnalysis

@dataclass
class SolvedExample:
    """A solved ARC task with its solution."""
    task_id: str
    task: ARCTask
    solution_code: str
    hypothesis_text: str
    features: Dict[str, float] = field(default_factory=dict)

class ExampleLibrary:
    """Library of solved examples for few-shot learning."""

    def __init__(self, cache_path: Optional[Path] = None):
        self.examples: Dict[str, SolvedExample] = {}
        self.analyzer = GridAnalyzer()
        self.cache_path = cache_path
        if cache_path and cache_path.exists():
            self._load_cache()

    def add_solved_task(self, task: ARCTask, solution_code: str, hypothesis_text: str):
        """Add a solved task to the library."""
        features = self._extract_features(task)
        example = SolvedExample(
            task_id=task.task_id,
            task=task,
            solution_code=solution_code,
            hypothesis_text=hypothesis_text,
            features=features
        )
        self.examples[task.task_id] = example
        self._save_cache()

    def find_similar(self, task: ARCTask, k: int = 3) -> List[SolvedExample]:
        """Find k most similar solved tasks."""
        if not self.examples:
            return []

        target_features = self._extract_features(task)

        # Compute similarity scores
        scores = []
        for example in self.examples.values():
            similarity = self._compute_similarity(target_features, example.features)
            scores.append((similarity, example))

        # Return top k
        scores.sort(key=lambda x: x[0], reverse=True)
        return [ex for _, ex in scores[:k]]

    def format_as_examples(self, examples: List[SolvedExample]) -> str:
        """Format similar tasks as few-shot examples for prompts."""
        if not examples:
            return ""

        text = "\n\nHere are similar solved tasks for reference:\n"
        for i, ex in enumerate(examples, 1):
            text += f"\n--- Example {i}: {ex.task_id} ---\n"
            text += f"Hypothesis: {ex.hypothesis_text}\n"
            text += f"Solution approach:\n```python\n{ex.solution_code[:500]}\n```\n"
        return text

    def _extract_features(self, task: ARCTask) -> Dict[str, float]:
        """Extract numerical features from a task for similarity comparison."""
        features = {}

        for i, pair in enumerate(task.train_pairs[:3]):  # Max 3 pairs
            in_analysis = self.analyzer.analyze(pair.input)
            out_analysis = self.analyzer.analyze(pair.output)

            prefix = f"pair{i}_"
            features[f"{prefix}in_height"] = pair.input.height
            features[f"{prefix}in_width"] = pair.input.width
            features[f"{prefix}out_height"] = pair.output.height
            features[f"{prefix}out_width"] = pair.output.width
            features[f"{prefix}in_colors"] = len(in_analysis.colors_present)
            features[f"{prefix}out_colors"] = len(out_analysis.colors_present)
            features[f"{prefix}in_objects"] = in_analysis.num_objects
            features[f"{prefix}out_objects"] = out_analysis.num_objects
            features[f"{prefix}size_change"] = (pair.output.height * pair.output.width) / max(1, pair.input.height * pair.input.width)

        return features

    def _compute_similarity(self, f1: Dict[str, float], f2: Dict[str, float]) -> float:
        """Compute similarity between two feature vectors."""
        common_keys = set(f1.keys()) & set(f2.keys())
        if not common_keys:
            return 0.0

        # Normalized difference
        total_diff = 0.0
        for key in common_keys:
            max_val = max(abs(f1[key]), abs(f2[key]), 1.0)
            diff = abs(f1[key] - f2[key]) / max_val
            total_diff += diff

        avg_diff = total_diff / len(common_keys)
        return 1.0 - min(avg_diff, 1.0)

    def _save_cache(self):
        """Save library to cache file."""
        if not self.cache_path:
            return
        # Implement serialization
        pass

    def _load_cache(self):
        """Load library from cache file."""
        if not self.cache_path or not self.cache_path.exists():
            return
        # Implement deserialization
        pass

# Singleton
_library: Optional[ExampleLibrary] = None

def get_example_library() -> ExampleLibrary:
    global _library
    if _library is None:
        _library = ExampleLibrary()
    return _library
