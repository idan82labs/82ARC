"""
Safe Python code executor for ARC transformations.
Supports both in-process and subprocess sandbox modes.
"""
import ast
import copy
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from ..config import load_config
from ..models import ARCGrid, ARCPair, VerificationResult, TrainResult
from .grid_analyzer import hamming_distance, normalized_distance

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class ExecutionResult:
    """Result of code execution."""
    success: bool
    output: Optional[Any] = None
    error: Optional[str] = None
    error_type: Optional[str] = None
    execution_time_ms: float = 0.0
    stdout: str = ""

@dataclass
class ValidationResult:
    """Result of validating code against examples."""
    all_passed: bool
    num_passed: int
    num_total: int
    results: List[Dict]
    error_summary: Optional[str] = None

# ============================================================================
# IN-PROCESS EXECUTOR (Fast but less isolated)
# ============================================================================

SAFE_BUILTINS = {
    'abs': abs, 'all': all, 'any': any, 'bool': bool, 'dict': dict,
    'enumerate': enumerate, 'filter': filter, 'float': float,
    'frozenset': frozenset, 'hasattr': hasattr, 'getattr': getattr,
    'int': int, 'isinstance': isinstance, 'issubclass': issubclass,
    'iter': iter, 'len': len, 'list': list, 'map': map, 'max': max,
    'min': min, 'next': next, 'print': print, 'range': range,
    'repr': repr, 'reversed': reversed, 'round': round, 'set': set,
    'slice': slice, 'sorted': sorted, 'str': str, 'sum': sum,
    'tuple': tuple, 'type': type, 'zip': zip,
    'True': True, 'False': False, 'None': None,
    'Exception': Exception, 'ValueError': ValueError,
    'TypeError': TypeError, 'IndexError': IndexError,
    'KeyError': KeyError, 'AttributeError': AttributeError,
}

ALLOWED_MODULES = {
    'numpy': np, 'np': np,
    'copy': copy,
    'itertools': __import__('itertools'),
    'functools': __import__('functools'),
    'collections': __import__('collections'),
    'math': __import__('math'),
    'operator': __import__('operator'),
    # scipy modules for advanced grid operations (object detection, morphology)
    'scipy': __import__('scipy'),
    'scipy.ndimage': __import__('scipy.ndimage'),
}

def create_safe_globals() -> Dict[str, Any]:
    """Create safe execution environment."""
    builtins_with_import = dict(SAFE_BUILTINS)
    
    def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
        allowed = {'numpy', 'np', 'copy', 'itertools', 'functools', 'collections', 'math', 'operator', 'scipy', 'scipy.ndimage'}
        if name in allowed or name.startswith('scipy'):
            return ALLOWED_MODULES.get(name, __import__(name))
        raise ImportError(f"Import of '{name}' is not allowed")
    
    builtins_with_import['__import__'] = restricted_import
    
    safe_globals = {'__builtins__': builtins_with_import}
    safe_globals.update(ALLOWED_MODULES)
    return safe_globals

class InProcessExecutor:
    """Execute code in-process with restricted globals."""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._cache: Dict[str, ExecutionResult] = {}
    
    def execute(self, code: str, input_grid: List[List[int]], use_cache: bool = True) -> ExecutionResult:
        start_time = time.time()
        
        cache_key = f"{hash(code)}_{hash(str(input_grid))}"
        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]
        
        safe_globals = create_safe_globals()
        safe_globals['input_grid'] = np.array(input_grid, dtype=np.int32)
        
        wrapped_code = f"""
{code}

_result = transform(input_grid)
"""
        
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._exec_code, wrapped_code, safe_globals)
                try:
                    output = future.result(timeout=self.timeout)
                    if isinstance(output, np.ndarray):
                        output = output.tolist()
                    
                    result = ExecutionResult(
                        success=True,
                        output=output,
                        execution_time_ms=(time.time() - start_time) * 1000
                    )
                except FuturesTimeoutError:
                    result = ExecutionResult(
                        success=False,
                        error=f"Timeout after {self.timeout}s",
                        error_type="TimeoutError"
                    )
        except Exception as e:
            result = ExecutionResult(
                success=False,
                error=str(e),
                error_type=type(e).__name__
            )
        
        if use_cache:
            self._cache[cache_key] = result
        return result
    
    def _exec_code(self, code: str, globals_dict: Dict) -> Any:
        exec(code, globals_dict)
        return globals_dict.get('_result')

# ============================================================================
# SUBPROCESS EXECUTOR (More isolated, from ARC-SLM)
# ============================================================================

class SubprocessExecutor:
    """Execute code in isolated subprocess."""
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
    
    def execute(self, code: str, input_grid: List[List[int]], use_cache: bool = False) -> ExecutionResult:
        start_time = time.time()
        
        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = f"{tmpdir}/solution.py"
            input_path = f"{tmpdir}/input.json"
            output_path = f"{tmpdir}/output.json"
            runner_path = f"{tmpdir}/run.py"
            
            # Write the solution code
            with open(script_path, "w") as f:
                f.write(code)
            
            # Write input
            with open(input_path, "w") as f:
                json.dump({"grid": input_grid}, f)
            
            # Write runner
            runner_code = textwrap.dedent(f'''
                import json
                import sys
                import numpy as np
                sys.path.insert(0, "{tmpdir}")
                
                try:
                    from solution import transform
                    with open("{input_path}", "r") as f:
                        data = json.load(f)
                    
                    grid = np.array(data["grid"], dtype=np.int32)
                    result = transform(grid)
                    
                    if hasattr(result, 'tolist'):
                        result = result.tolist()
                    
                    with open("{output_path}", "w") as f:
                        json.dump({{"output": result}}, f)
                except Exception as e:
                    with open("{output_path}", "w") as f:
                        json.dump({{"error": str(e), "error_type": type(e).__name__}}, f)
            ''')
            
            with open(runner_path, "w") as f:
                f.write(runner_code)
            
            try:
                proc = subprocess.run(
                    [sys.executable, runner_path],
                    cwd=tmpdir,
                    timeout=self.timeout,
                    capture_output=True,
                    text=True,
                )
                
                if proc.returncode != 0 and not os.path.exists(output_path):
                    return ExecutionResult(
                        success=False,
                        error=proc.stderr or "Unknown error",
                        error_type="RuntimeError",
                        stdout=proc.stdout,
                        execution_time_ms=(time.time() - start_time) * 1000
                    )
                
                with open(output_path, "r") as f:
                    result_data = json.load(f)
                
                if "error" in result_data:
                    return ExecutionResult(
                        success=False,
                        error=result_data["error"],
                        error_type=result_data.get("error_type", "RuntimeError"),
                        stdout=proc.stdout,
                        execution_time_ms=(time.time() - start_time) * 1000
                    )
                
                return ExecutionResult(
                    success=True,
                    output=result_data["output"],
                    stdout=proc.stdout,
                    execution_time_ms=(time.time() - start_time) * 1000
                )
                
            except subprocess.TimeoutExpired:
                return ExecutionResult(
                    success=False,
                    error=f"Timeout after {self.timeout}s",
                    error_type="TimeoutError",
                    execution_time_ms=(time.time() - start_time) * 1000
                )
            except Exception as e:
                return ExecutionResult(
                    success=False,
                    error=str(e),
                    error_type=type(e).__name__,
                    execution_time_ms=(time.time() - start_time) * 1000
                )

# ============================================================================
# UNIFIED CODE EXECUTOR
# ============================================================================

class CodeExecutor:
    """
    Unified code executor supporting both in-process and subprocess modes.
    """
    
    def __init__(self, mode: str = None, timeout: float = None):
        cfg = load_config()
        self.mode = mode or cfg.tools.sandbox_mode
        self.timeout = timeout or cfg.tools.execution_timeout
        
        if self.mode == "subprocess":
            self._executor = SubprocessExecutor(self.timeout)
        else:
            self._executor = InProcessExecutor(self.timeout)
        
        self._cache: Dict[str, ExecutionResult] = {}
    
    def execute(self, code: str, input_grid: List[List[int]], use_cache: bool = True) -> ExecutionResult:
        """Execute transformation code on an input grid."""
        return self._executor.execute(code, input_grid, use_cache)
    
    def validate_against_examples(
        self,
        code: str,
        train_pairs: List[ARCPair],
    ) -> ValidationResult:
        """Validate code against all training examples."""
        results = []
        num_passed = 0
        
        for i, pair in enumerate(train_pairs):
            input_grid = pair.input.cells
            expected_output = pair.output.cells
            
            exec_result = self.execute(code, input_grid)
            
            if exec_result.success:
                actual = exec_result.output
                if isinstance(actual, np.ndarray):
                    actual = actual.tolist()
                
                matches = actual == expected_output
                
                if matches:
                    num_passed += 1
                    results.append({
                        "example_idx": i,
                        "passed": True,
                        "actual": actual,
                        "expected": expected_output,
                    })
                else:
                    diff = self._compute_diff(actual, expected_output)
                    results.append({
                        "example_idx": i,
                        "passed": False,
                        "actual": actual,
                        "expected": expected_output,
                        "diff": diff,
                    })
            else:
                results.append({
                    "example_idx": i,
                    "passed": False,
                    "error": exec_result.error,
                    "error_type": exec_result.error_type,
                })
        
        all_passed = num_passed == len(train_pairs)
        
        # Generate error summary
        error_summary = None
        if not all_passed:
            failed = [r for r in results if not r.get("passed")]
            if failed:
                first_fail = failed[0]
                if "error" in first_fail:
                    error_summary = f"Example {first_fail['example_idx']}: {first_fail['error_type']}: {first_fail['error']}"
                elif "diff" in first_fail:
                    error_summary = f"Example {first_fail['example_idx']}: {first_fail['diff']['summary']}"
        
        return ValidationResult(
            all_passed=all_passed,
            num_passed=num_passed,
            num_total=len(train_pairs),
            results=results,
            error_summary=error_summary
        )
    
    def _compute_diff(self, actual: List, expected: List) -> Dict:
        """Compute difference between actual and expected grids."""
        if not isinstance(actual, list) or not isinstance(expected, list):
            return {"summary": "Output is not a valid grid"}
        
        actual_arr = np.array(actual) if actual else np.array([[]])
        expected_arr = np.array(expected)
        
        if actual_arr.shape != expected_arr.shape:
            return {
                "summary": f"Wrong dimensions: got {actual_arr.shape}, expected {expected_arr.shape}",
                "actual_shape": list(actual_arr.shape),
                "expected_shape": list(expected_arr.shape),
            }
        
        if actual_arr.size == 0 or expected_arr.size == 0:
            return {"summary": "Empty grid"}
        
        mismatches = np.argwhere(actual_arr != expected_arr)
        num_wrong = len(mismatches)
        total_cells = actual_arr.size
        
        mismatch_details = []
        for row, col in mismatches[:5]:
            mismatch_details.append({
                "row": int(row),
                "col": int(col),
                "actual": int(actual_arr[row, col]),
                "expected": int(expected_arr[row, col]),
            })
        
        return {
            "summary": f"{num_wrong}/{total_cells} cells wrong ({100*num_wrong/total_cells:.1f}%)",
            "num_wrong": num_wrong,
            "total_cells": total_cells,
            "percent_correct": 100 * (total_cells - num_wrong) / total_cells,
            "first_mismatches": mismatch_details,
        }
    
    def clear_cache(self):
        """Clear execution cache."""
        self._cache.clear()
        if hasattr(self._executor, '_cache'):
            self._executor._cache.clear()

# ============================================================================
# SINGLETON
# ============================================================================

_executor: Optional[CodeExecutor] = None

def get_executor() -> CodeExecutor:
    global _executor
    if _executor is None:
        _executor = CodeExecutor()
    return _executor
