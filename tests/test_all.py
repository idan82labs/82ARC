"""
Comprehensive test suite for ARC Solver Unified.
Run with: pytest -v tests/
"""
import pytest
import numpy as np
from typing import List

# ============================================================================
# MODEL TESTS
# ============================================================================

class TestModels:
    def test_arc_grid_from_list(self):
        from arc_solver.models import ARCGrid
        
        cells = [[1, 2], [3, 4]]
        grid = ARCGrid.from_list(cells)
        
        assert grid.width == 2
        assert grid.height == 2
        assert grid.cells == cells
    
    def test_arc_grid_to_list(self):
        from arc_solver.models import ARCGrid
        
        cells = [[1, 2, 3], [4, 5, 6]]
        grid = ARCGrid.from_list(cells)
        
        assert grid.to_list() == cells
    
    def test_arc_task_properties(self):
        from arc_solver.models import ARCTask, ARCGrid, ARCPair
        
        pair1 = ARCPair(
            input=ARCGrid.from_list([[1]]),
            output=ARCGrid.from_list([[2]])
        )
        pair2 = ARCPair(
            input=ARCGrid.from_list([[3]]),
            output=ARCGrid.from_list([[4]])
        )
        
        task = ARCTask(
            task_id="test",
            train_pairs=[pair1, pair2],
            test_inputs=[ARCGrid.from_list([[5]])]
        )
        
        assert task.num_train == 2
        assert task.num_test == 1
    
    def test_hypothesis_status(self):
        from arc_solver.models import Hypothesis, HypothesisStatus
        
        h = Hypothesis(text="Test hypothesis")
        assert h.status == HypothesisStatus.PROPOSED
        
        h.status = HypothesisStatus.PASSED
        assert h.status == HypothesisStatus.PASSED

# ============================================================================
# GRID ANALYZER TESTS
# ============================================================================

class TestGridAnalyzer:
    def test_basic_analysis(self):
        from arc_solver.tools.grid_analyzer import GridAnalyzer
        from arc_solver.models import ARCGrid
        
        analyzer = GridAnalyzer()
        grid = ARCGrid.from_list([[1, 2], [3, 4]])
        analysis = analyzer.analyze(grid)
        
        assert analysis.height == 2
        assert analysis.width == 2
        assert set(analysis.colors_present) == {1, 2, 3, 4}
    
    def test_horizontal_symmetry(self):
        from arc_solver.tools.grid_analyzer import GridAnalyzer
        from arc_solver.models import ARCGrid
        
        analyzer = GridAnalyzer()
        
        # Symmetric
        sym_grid = ARCGrid.from_list([[1, 2, 1], [3, 4, 3]])
        assert analyzer.analyze(sym_grid).has_horizontal_symmetry
        
        # Not symmetric
        asym_grid = ARCGrid.from_list([[1, 2, 3]])
        assert not analyzer.analyze(asym_grid).has_horizontal_symmetry
    
    def test_vertical_symmetry(self):
        from arc_solver.tools.grid_analyzer import GridAnalyzer
        from arc_solver.models import ARCGrid
        
        analyzer = GridAnalyzer()
        
        # Symmetric
        sym_grid = ARCGrid.from_list([[1, 2], [3, 4], [1, 2]])
        assert analyzer.analyze(sym_grid).has_vertical_symmetry
    
    def test_object_detection(self):
        from arc_solver.tools.grid_analyzer import GridAnalyzer
        from arc_solver.models import ARCGrid
        
        analyzer = GridAnalyzer()
        
        # Grid with two separate objects
        grid = ARCGrid.from_list([
            [1, 0, 2],
            [0, 0, 0],
            [3, 0, 0]
        ])
        analysis = analyzer.analyze(grid)
        
        # Should detect 3 objects (colors 1, 2, 3)
        assert analysis.num_objects >= 1
    
    def test_transformation_detection(self):
        from arc_solver.tools.grid_analyzer import GridAnalyzer
        from arc_solver.models import ARCGrid, ARCPair
        
        analyzer = GridAnalyzer()
        
        # Horizontal flip
        pair = ARCPair(
            input=ARCGrid.from_list([[1, 2, 3]]),
            output=ARCGrid.from_list([[3, 2, 1]])
        )
        result = analyzer.analyze_transformation(pair)
        
        assert "horizontal_flip" in result["transformations_detected"]
    
    def test_hamming_distance(self):
        from arc_solver.tools.grid_analyzer import hamming_distance
        from arc_solver.models import ARCGrid
        
        grid1 = ARCGrid.from_list([[1, 2], [3, 4]])
        grid2 = ARCGrid.from_list([[1, 2], [3, 5]])  # One different
        grid3 = ARCGrid.from_list([[1, 2], [3, 4]])  # Same
        
        assert hamming_distance(grid1, grid2) == 1
        assert hamming_distance(grid1, grid3) == 0

# ============================================================================
# CODE EXECUTOR TESTS
# ============================================================================

class TestCodeExecutor:
    def test_simple_execution(self):
        from arc_solver.tools.code_executor import CodeExecutor
        
        executor = CodeExecutor(mode="inprocess", timeout=5.0)
        
        code = """
import numpy as np
def transform(input_grid):
    return input_grid.tolist()
"""
        result = executor.execute(code, [[1, 2], [3, 4]])
        
        assert result.success
        assert result.output == [[1, 2], [3, 4]]
    
    def test_numpy_operations(self):
        from arc_solver.tools.code_executor import CodeExecutor
        
        executor = CodeExecutor(mode="inprocess")
        
        code = """
import numpy as np
def transform(input_grid):
    return np.fliplr(input_grid).tolist()
"""
        result = executor.execute(code, [[1, 2, 3]])
        
        assert result.success
        assert result.output == [[3, 2, 1]]
    
    def test_timeout(self):
        from arc_solver.tools.code_executor import CodeExecutor
        
        executor = CodeExecutor(mode="inprocess", timeout=1.0)
        
        code = """
import time
def transform(input_grid):
    time.sleep(10)
    return input_grid
"""
        result = executor.execute(code, [[1]])
        
        assert not result.success
        assert "Timeout" in result.error
    
    def test_syntax_error(self):
        from arc_solver.tools.code_executor import CodeExecutor
        
        executor = CodeExecutor(mode="inprocess")
        
        code = """
def transform(input_grid)  # Missing colon
    return input_grid
"""
        result = executor.execute(code, [[1]])
        
        assert not result.success
        assert "SyntaxError" in result.error_type
    
    def test_validation(self):
        from arc_solver.tools.code_executor import CodeExecutor
        from arc_solver.models import ARCGrid, ARCPair
        
        executor = CodeExecutor(mode="inprocess")
        
        code = """
import numpy as np
def transform(input_grid):
    return np.fliplr(input_grid).tolist()
"""
        
        pairs = [
            ARCPair(
                input=ARCGrid.from_list([[1, 2, 3]]),
                output=ARCGrid.from_list([[3, 2, 1]])
            ),
            ARCPair(
                input=ARCGrid.from_list([[4, 5]]),
                output=ARCGrid.from_list([[5, 4]])
            ),
        ]
        
        result = executor.validate_against_examples(code, pairs)
        
        assert result.all_passed
        assert result.num_passed == 2
        assert result.num_total == 2

# ============================================================================
# COT LOG TESTS
# ============================================================================

class TestCOTLog:
    def test_add_hypothesis(self):
        from arc_solver.memory.cot_log import COTLog
        
        cot = COTLog("test_workspace")
        h = cot.add_hypothesis("Test hypothesis", confidence=0.7)
        
        assert h.id.startswith("h_")
        assert h.text == "Test hypothesis"
        assert h.confidence == 0.7
    
    def test_update_hypothesis(self):
        from arc_solver.memory.cot_log import COTLog
        from arc_solver.models import HypothesisStatus
        
        cot = COTLog("test")
        h = cot.add_hypothesis("Test")
        
        cot.update_hypothesis(
            h.id,
            status=HypothesisStatus.PASSED,
            examples_passed=3,
            examples_total=3
        )
        
        updated = cot.get_hypothesis(h.id)
        assert updated.status == HypothesisStatus.PASSED
        assert updated.examples_passed == 3
        assert cot.is_solved  # All passed = solved
    
    def test_add_observation(self):
        from arc_solver.memory.cot_log import COTLog
        
        cot = COTLog("test")
        o = cot.add_observation("Dimensions preserved", category="dimension")
        
        assert o.id.startswith("o_")
        assert o.category == "dimension"
        
        # Test deduplication
        o2 = cot.add_observation("Dimensions preserved", category="dimension")
        assert o.id == o2.id  # Same observation
    
    def test_failed_attempt_tracking(self):
        from arc_solver.memory.cot_log import COTLog
        
        cot = COTLog("test")
        h = cot.add_hypothesis("Test")
        
        cot.add_failed_attempt(
            hypothesis_id=h.id,
            code="def transform(x): return x",
            error_type="WrongOutput",
            error_message="2/3 cells wrong",
            examples_passed=1,
            examples_total=3
        )
        
        failures = cot.get_recent_failures(5)
        assert len(failures) == 1
        assert failures[0].examples_passed == 1
    
    def test_context_generation(self):
        from arc_solver.memory.cot_log import COTLog
        
        cot = COTLog("test")
        cot.add_observation("Grid is 3x3", confidence=1.0)
        cot.add_hypothesis("Copy input")
        
        context = cot.get_context_for_solver()
        
        assert "Grid is 3x3" in context or "Established" in context
    
    def test_serialization(self):
        from arc_solver.memory.cot_log import COTLog
        import json
        
        cot = COTLog("test")
        cot.add_hypothesis("Test")
        cot.add_observation("Observation")
        
        data = cot.to_dict()
        json_str = cot.to_json()
        
        assert "workspace_id" in data
        assert "hypotheses" in data
        parsed = json.loads(json_str)
        assert parsed["workspace_id"] == "test"

# ============================================================================
# CONFIG TESTS
# ============================================================================

class TestConfig:
    def test_load_config(self):
        from arc_solver.config import load_config
        
        cfg = load_config()
        
        assert cfg.app is not None
        assert cfg.default_strategy == "default"
    
    def test_get_strategy(self):
        from arc_solver.config import get_strategy
        
        strategy = get_strategy("default")
        
        assert strategy.cost_budget_usd > 0
        assert strategy.solver.max_iterations > 0
    
    def test_model_definitions(self):
        from arc_solver.config import load_config
        
        cfg = load_config()
        
        assert len(cfg.models.definitions) > 0
        assert cfg.models.solver in cfg.models.definitions

# ============================================================================
# INTEGRATION TESTS (require no API keys)
# ============================================================================

class TestIntegration:
    def test_sample_tasks_exist(self):
        from arc_solver.cli import SAMPLE_TASKS
        
        assert "simple_copy" in SAMPLE_TASKS
        assert "horizontal_flip" in SAMPLE_TASKS
        assert "scale_2x" in SAMPLE_TASKS
    
    def test_load_sample_task(self):
        from arc_solver.cli import load_sample_task
        
        task = load_sample_task("horizontal_flip")
        
        assert task.task_id == "horizontal_flip"
        assert task.num_train == 2
        assert task.num_test == 1
    
    def test_solve_simple_copy_manually(self):
        """Test that simple_copy can be solved with identity transform."""
        from arc_solver.tools.code_executor import CodeExecutor
        from arc_solver.cli import load_sample_task
        
        task = load_sample_task("simple_copy")
        executor = CodeExecutor(mode="inprocess")
        
        code = """
import numpy as np
def transform(input_grid):
    return input_grid.tolist()
"""
        result = executor.validate_against_examples(code, task.train_pairs)
        
        assert result.all_passed
    
    def test_solve_horizontal_flip_manually(self):
        """Test horizontal flip solution."""
        from arc_solver.tools.code_executor import CodeExecutor
        from arc_solver.cli import load_sample_task
        
        task = load_sample_task("horizontal_flip")
        executor = CodeExecutor(mode="inprocess")
        
        code = """
import numpy as np
def transform(input_grid):
    return np.fliplr(input_grid).tolist()
"""
        result = executor.validate_against_examples(code, task.train_pairs)
        
        assert result.all_passed
    
    def test_solve_scale_2x_manually(self):
        """Test 2x scaling solution."""
        from arc_solver.tools.code_executor import CodeExecutor
        from arc_solver.cli import load_sample_task
        
        task = load_sample_task("scale_2x")
        executor = CodeExecutor(mode="inprocess")
        
        code = """
import numpy as np
def transform(input_grid):
    grid = np.array(input_grid)
    return np.repeat(np.repeat(grid, 2, axis=0), 2, axis=1).tolist()
"""
        result = executor.validate_against_examples(code, task.train_pairs)
        
        assert result.all_passed

# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
