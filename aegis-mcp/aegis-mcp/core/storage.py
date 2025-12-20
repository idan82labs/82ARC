"""
Aegis MCP Operation State Storage
Handles persistence of operation state and artifacts.
"""
import json
from datetime import datetime
from typing import Dict, Optional, List
from pathlib import Path

class OperationStorage:
    """In-memory operation storage with optional file persistence."""
    
    def __init__(self, persist_path: str = None):
        self._operations: Dict[str, dict] = {}
        self._persist_path = Path(persist_path) if persist_path else None
        
        if self._persist_path and self._persist_path.exists():
            self._load_from_disk()
    
    def save(self, operation: dict) -> bool:
        """Save operation state."""
        op_id = operation.get("id")
        if not op_id:
            return False
            
        operation["updated_at"] = datetime.utcnow().isoformat()
        self._operations[op_id] = operation
        
        if self._persist_path:
            self._persist_to_disk()
        
        return True
    
    def load(self, operation_id: str) -> Optional[dict]:
        """Load operation state."""
        return self._operations.get(operation_id)
    
    def delete(self, operation_id: str) -> bool:
        """Delete operation state."""
        if operation_id in self._operations:
            del self._operations[operation_id]
            if self._persist_path:
                self._persist_to_disk()
            return True
        return False
    
    def list_all(self) -> List[dict]:
        """List all operations."""
        return list(self._operations.values())
    
    def list_active(self) -> List[dict]:
        """List active (non-completed, non-aborted) operations."""
        return [
            op for op in self._operations.values()
            if op.get("status") not in ["completed", "aborted"]
        ]
    
    def _persist_to_disk(self):
        """Write operations to disk."""
        if not self._persist_path:
            return
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._persist_path, 'w') as f:
            json.dump(self._operations, f, indent=2, default=str)
    
    def _load_from_disk(self):
        """Load operations from disk."""
        if not self._persist_path or not self._persist_path.exists():
            return
        try:
            with open(self._persist_path, 'r') as f:
                self._operations = json.load(f)
        except (json.JSONDecodeError, IOError):
            self._operations = {}


class ArtifactStorage:
    """Storage for operation artifacts (payloads, loot, etc)."""

    def __init__(self, base_path: str = "/tmp/aegis/artifacts"):
        self._base_path = Path(base_path)
        self._base_path.mkdir(parents=True, exist_ok=True)
    
    def store(self, operation_id: str, artifact_name: str, content: bytes) -> str:
        """Store artifact and return path."""
        op_dir = self._base_path / operation_id
        op_dir.mkdir(parents=True, exist_ok=True)
        
        artifact_path = op_dir / artifact_name
        with open(artifact_path, 'wb') as f:
            f.write(content)
        
        return str(artifact_path)
    
    def retrieve(self, operation_id: str, artifact_name: str) -> Optional[bytes]:
        """Retrieve artifact content."""
        artifact_path = self._base_path / operation_id / artifact_name
        if not artifact_path.exists():
            return None
        
        with open(artifact_path, 'rb') as f:
            return f.read()
    
    def list_artifacts(self, operation_id: str) -> List[str]:
        """List artifacts for operation."""
        op_dir = self._base_path / operation_id
        if not op_dir.exists():
            return []
        return [f.name for f in op_dir.iterdir() if f.is_file()]
    
    def delete_all(self, operation_id: str) -> int:
        """Delete all artifacts for operation. Returns count deleted."""
        op_dir = self._base_path / operation_id
        if not op_dir.exists():
            return 0
        
        count = 0
        for f in op_dir.iterdir():
            if f.is_file():
                f.unlink()
                count += 1
        
        op_dir.rmdir()
        return count


# Global instances
_operation_storage: Optional[OperationStorage] = None
_artifact_storage: Optional[ArtifactStorage] = None

def get_operation_storage() -> OperationStorage:
    """Get singleton operation storage instance."""
    global _operation_storage
    if _operation_storage is None:
        _operation_storage = OperationStorage()
    return _operation_storage

def get_artifact_storage() -> ArtifactStorage:
    """Get singleton artifact storage instance."""
    global _artifact_storage
    if _artifact_storage is None:
        _artifact_storage = ArtifactStorage()
    return _artifact_storage
