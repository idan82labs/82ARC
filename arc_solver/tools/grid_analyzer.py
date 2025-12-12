"""
Grid analyzer for ARC tasks.
Extracts objects, colors, symmetries, and patterns from grids.
"""
import numpy as np
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from scipy import ndimage

from ..models import ARCGrid, ARCPair

# ============================================================================
# DATA CLASSES
# ============================================================================

@dataclass
class GridObject:
    """A connected component (object) in a grid."""
    id: int
    color: int
    pixels: List[Tuple[int, int]]
    bounding_box: Tuple[int, int, int, int]  # (min_row, min_col, max_row, max_col)
    width: int
    height: int
    area: int
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "color": self.color,
            "num_pixels": len(self.pixels),
            "bounding_box": self.bounding_box,
            "width": self.width,
            "height": self.height,
            "area": self.area,
        }

@dataclass
class GridAnalysis:
    """Complete analysis of a grid."""
    height: int
    width: int
    colors_present: List[int]
    color_counts: Dict[int, int]
    background_color: int
    objects: List[GridObject]
    num_objects: int
    has_horizontal_symmetry: bool
    has_vertical_symmetry: bool
    has_rotational_symmetry: bool
    has_diagonal_symmetry: bool
    is_uniform: bool
    has_repeated_pattern: bool
    has_border: bool
    border_color: Optional[int]
    is_square: bool
    unique_rows: int
    unique_cols: int
    
    def to_dict(self) -> Dict:
        return {
            "dimensions": {"height": self.height, "width": self.width},
            "colors": {
                "present": self.colors_present,
                "counts": self.color_counts,
                "background": self.background_color,
            },
            "objects": {
                "count": self.num_objects,
                "details": [obj.to_dict() for obj in self.objects],
            },
            "symmetry": {
                "horizontal": self.has_horizontal_symmetry,
                "vertical": self.has_vertical_symmetry,
                "rotational": self.has_rotational_symmetry,
                "diagonal": self.has_diagonal_symmetry,
            },
            "patterns": {
                "uniform": self.is_uniform,
                "repeated": self.has_repeated_pattern,
                "has_border": self.has_border,
                "border_color": self.border_color,
            },
            "properties": {
                "is_square": self.is_square,
                "unique_rows": self.unique_rows,
                "unique_cols": self.unique_cols,
            }
        }
    
    def to_summary(self) -> str:
        """Generate human-readable summary."""
        lines = [f"Grid: {self.height}×{self.width}"]
        lines.append(f"Colors: {self.colors_present} (background={self.background_color})")
        lines.append(f"Objects: {self.num_objects}")
        
        symmetries = []
        if self.has_horizontal_symmetry: symmetries.append("horizontal")
        if self.has_vertical_symmetry: symmetries.append("vertical")
        if self.has_rotational_symmetry: symmetries.append("rotational")
        if self.has_diagonal_symmetry: symmetries.append("diagonal")
        if symmetries:
            lines.append(f"Symmetry: {', '.join(symmetries)}")
        
        if self.has_border:
            lines.append(f"Border: color {self.border_color}")
        
        return "\n".join(lines)

# ============================================================================
# GRID ANALYZER
# ============================================================================

class GridAnalyzer:
    """Analyzes ARC grids to extract structure and patterns."""
    
    def __init__(self):
        self._cache: Dict[str, GridAnalysis] = {}
    
    def analyze(self, grid: ARCGrid, use_cache: bool = True) -> GridAnalysis:
        """Perform complete analysis of a grid."""
        cells = grid.cells
        cache_key = str(cells)
        if use_cache and cache_key in self._cache:
            return self._cache[cache_key]
        
        arr = np.array(cells, dtype=np.int32)
        height, width = arr.shape
        
        # Color analysis
        colors_present, color_counts, background_color = self._analyze_colors(arr)
        
        # Object detection
        objects = self._detect_objects(arr, background_color)
        
        # Symmetry detection
        h_sym = self._check_horizontal_symmetry(arr)
        v_sym = self._check_vertical_symmetry(arr)
        r_sym = self._check_rotational_symmetry(arr)
        d_sym = self._check_diagonal_symmetry(arr)
        
        # Pattern detection
        is_uniform = len(colors_present) == 1
        has_repeated = self._check_repeated_pattern(arr)
        has_border, border_color = self._check_border(arr)
        
        # Grid properties
        is_square = height == width
        unique_rows = len(set(tuple(row) for row in arr.tolist()))
        unique_cols = len(set(tuple(col) for col in arr.T.tolist()))
        
        analysis = GridAnalysis(
            height=height,
            width=width,
            colors_present=colors_present,
            color_counts=color_counts,
            background_color=background_color,
            objects=objects,
            num_objects=len(objects),
            has_horizontal_symmetry=h_sym,
            has_vertical_symmetry=v_sym,
            has_rotational_symmetry=r_sym,
            has_diagonal_symmetry=d_sym,
            is_uniform=is_uniform,
            has_repeated_pattern=has_repeated,
            has_border=has_border,
            border_color=border_color,
            is_square=is_square,
            unique_rows=unique_rows,
            unique_cols=unique_cols,
        )
        
        if use_cache:
            self._cache[cache_key] = analysis
        
        return analysis
    
    def analyze_from_list(self, cells: List[List[int]], use_cache: bool = True) -> GridAnalysis:
        """Analyze from a raw cell list."""
        grid = ARCGrid.from_list(cells)
        return self.analyze(grid, use_cache)
    
    def _analyze_colors(self, arr: np.ndarray) -> Tuple[List[int], Dict[int, int], int]:
        unique, counts = np.unique(arr, return_counts=True)
        color_counts = dict(zip(unique.tolist(), counts.tolist()))
        colors_present = sorted(unique.tolist())
        
        if 0 in color_counts:
            background_color = 0
        else:
            background_color = max(color_counts.keys(), key=lambda c: color_counts[c])
        
        return colors_present, color_counts, background_color
    
    def _detect_objects(self, arr: np.ndarray, background: int) -> List[GridObject]:
        objects = []
        obj_id = 0
        
        for color in np.unique(arr):
            if color == background:
                continue
            
            mask = (arr == color).astype(np.int32)
            labeled, num_features = ndimage.label(mask)
            
            for i in range(1, num_features + 1):
                pixels = list(zip(*np.where(labeled == i)))
                if not pixels:
                    continue
                
                rows, cols = zip(*pixels)
                min_row, max_row = min(rows), max(rows)
                min_col, max_col = min(cols), max(cols)
                
                obj = GridObject(
                    id=obj_id,
                    color=int(color),
                    pixels=[(int(r), int(c)) for r, c in pixels],
                    bounding_box=(min_row, min_col, max_row, max_col),
                    width=max_col - min_col + 1,
                    height=max_row - min_row + 1,
                    area=len(pixels),
                )
                objects.append(obj)
                obj_id += 1
        
        return objects
    
    def _check_horizontal_symmetry(self, arr: np.ndarray) -> bool:
        return np.array_equal(arr, np.fliplr(arr))
    
    def _check_vertical_symmetry(self, arr: np.ndarray) -> bool:
        return np.array_equal(arr, np.flipud(arr))
    
    def _check_rotational_symmetry(self, arr: np.ndarray) -> bool:
        return np.array_equal(arr, np.rot90(arr, 2))
    
    def _check_diagonal_symmetry(self, arr: np.ndarray) -> bool:
        if arr.shape[0] != arr.shape[1]:
            return False
        return np.array_equal(arr, arr.T)
    
    def _check_repeated_pattern(self, arr: np.ndarray) -> bool:
        h, w = arr.shape
        
        for period in range(1, w // 2 + 1):
            if w % period == 0:
                tile = arr[:, :period]
                repeated = np.tile(tile, (1, w // period))
                if np.array_equal(arr, repeated):
                    return True
        
        for period in range(1, h // 2 + 1):
            if h % period == 0:
                tile = arr[:period, :]
                repeated = np.tile(tile, (h // period, 1))
                if np.array_equal(arr, repeated):
                    return True
        
        return False
    
    def _check_border(self, arr: np.ndarray) -> Tuple[bool, Optional[int]]:
        h, w = arr.shape
        if h < 3 or w < 3:
            return False, None
        
        top = arr[0, :]
        bottom = arr[-1, :]
        left = arr[:, 0]
        right = arr[:, -1]
        
        border_pixels = np.concatenate([top, bottom, left[1:-1], right[1:-1]])
        
        if len(np.unique(border_pixels)) == 1:
            border_color = int(border_pixels[0])
            interior = arr[1:-1, 1:-1]
            if not np.all(interior == border_color):
                return True, border_color
        
        return False, None
    
    def compare_grids(self, grid1: ARCGrid, grid2: ARCGrid) -> Dict[str, Any]:
        """Compare two grids and identify differences."""
        arr1 = np.array(grid1.cells)
        arr2 = np.array(grid2.cells)
        
        result = {
            "same_dimensions": arr1.shape == arr2.shape,
            "grid1_shape": arr1.shape,
            "grid2_shape": arr2.shape,
        }
        
        if arr1.shape == arr2.shape:
            diff_mask = arr1 != arr2
            result["num_different_cells"] = int(np.sum(diff_mask))
            result["percent_different"] = float(np.mean(diff_mask) * 100)
            result["different_positions"] = [
                {"row": int(r), "col": int(c), "val1": int(arr1[r,c]), "val2": int(arr2[r,c])}
                for r, c in zip(*np.where(diff_mask))
            ][:10]
            
            colors1 = set(np.unique(arr1).tolist())
            colors2 = set(np.unique(arr2).tolist())
            result["colors_added"] = list(colors2 - colors1)
            result["colors_removed"] = list(colors1 - colors2)
        
        return result
    
    def analyze_transformation(self, pair: ARCPair) -> Dict[str, Any]:
        """Analyze the transformation in an input-output pair."""
        in_analysis = self.analyze(pair.input)
        out_analysis = self.analyze(pair.output)
        comparison = self.compare_grids(pair.input, pair.output)
        
        in_arr = np.array(pair.input.cells)
        out_arr = np.array(pair.output.cells)
        
        transformations = []
        
        # Check rotations
        for k in [1, 2, 3]:
            if np.array_equal(np.rot90(in_arr, k), out_arr):
                transformations.append(f"rotation_{k*90}_degrees")
        
        # Check flips
        if np.array_equal(np.fliplr(in_arr), out_arr):
            transformations.append("horizontal_flip")
        if np.array_equal(np.flipud(in_arr), out_arr):
            transformations.append("vertical_flip")
        
        # Check transpose
        if in_arr.shape[0] == out_arr.shape[1] and in_arr.shape[1] == out_arr.shape[0]:
            if np.array_equal(in_arr.T, out_arr):
                transformations.append("transpose")
        
        # Check color mapping
        if in_arr.shape == out_arr.shape:
            unique_in = np.unique(in_arr)
            color_map = {}
            is_color_map = True
            for c in unique_in:
                mask = in_arr == c
                out_colors = np.unique(out_arr[mask])
                if len(out_colors) == 1:
                    color_map[int(c)] = int(out_colors[0])
                else:
                    is_color_map = False
                    break
            
            if is_color_map and color_map:
                transformations.append("color_mapping")
        
        # Check scaling
        if out_arr.shape[0] % in_arr.shape[0] == 0 and out_arr.shape[1] % in_arr.shape[1] == 0:
            scale_h = out_arr.shape[0] // in_arr.shape[0]
            scale_w = out_arr.shape[1] // in_arr.shape[1]
            if scale_h == scale_w and scale_h > 1:
                scaled = np.repeat(np.repeat(in_arr, scale_h, axis=0), scale_w, axis=1)
                if np.array_equal(scaled, out_arr):
                    transformations.append(f"scale_{scale_h}x")
        
        return {
            "input": in_analysis.to_dict(),
            "output": out_analysis.to_dict(),
            "comparison": comparison,
            "transformations_detected": transformations,
        }
    
    def clear_cache(self):
        self._cache.clear()

# ============================================================================
# ARC OPERATIONS (from ARC-SLM)
# ============================================================================

def hamming_distance(a: ARCGrid, b: ARCGrid) -> int:
    """Calculate Hamming distance between two grids."""
    if a.width != b.width or a.height != b.height:
        return max(a.width * a.height, b.width * b.height)
    dist = 0
    for y in range(a.height):
        for x in range(a.width):
            if a.cells[y][x] != b.cells[y][x]:
                dist += 1
    return dist

def normalized_distance(a: ARCGrid, b: ARCGrid) -> float:
    """Calculate normalized Hamming distance."""
    total = a.width * a.height
    if total == 0:
        return 0.0
    return hamming_distance(a, b) / total

def rotate_grid_90(grid: ARCGrid) -> ARCGrid:
    """Rotate grid 90 degrees counterclockwise."""
    rotated_cells = list(zip(*grid.cells[::-1]))
    new_cells = [list(row) for row in rotated_cells]
    return ARCGrid(width=grid.height, height=grid.width, cells=new_cells)

def flip_grid_horizontal(grid: ARCGrid) -> ARCGrid:
    """Flip grid horizontally."""
    new_cells = [row[::-1] for row in grid.cells]
    return ARCGrid(width=grid.width, height=grid.height, cells=new_cells)

def flip_grid_vertical(grid: ARCGrid) -> ARCGrid:
    """Flip grid vertically."""
    new_cells = grid.cells[::-1]
    return ARCGrid(width=grid.width, height=grid.height, cells=new_cells)

# ============================================================================
# SINGLETON
# ============================================================================

_analyzer: Optional[GridAnalyzer] = None

def get_analyzer() -> GridAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = GridAnalyzer()
    return _analyzer
