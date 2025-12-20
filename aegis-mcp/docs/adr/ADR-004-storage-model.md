# ADR-004: Storage Model

**Status:** Accepted (Revised)
**Date:** 2024-12-20
**Author:** Aegis Team
**Revision:** 2 - Adding path traversal protection and encryption at rest

## Context

Aegis needs persistent storage for:
- Runs, Scopes, Targets (structured data)
- Evidence/artifacts (potentially large blobs)
- Audit logs (append-only, immutable)
- Configuration (key-value)
- **Principals and API keys (encrypted)**

Requirements:
- Self-contained (no external database required)
- Portable (single file or directory)
- Queryable for reporting
- Pluggable to external stores later
- **Path traversal protection**
- **Encryption at rest for sensitive data**

## Decision

### Directory Structure (Secure)

```
aegis_data/
├── aegis.db              # SQLite database (encrypted sensitive columns)
├── artifacts/            # Binary artifacts (path-validated)
│   └── {sanitized_run_id}/
│       ├── evidence_001.json
│       └── ...
├── audit.log             # Append-only audit log (signed entries)
├── keys/                 # Encryption keys (restricted permissions)
│   ├── data.key          # Fernet key for data encryption (mode 0600)
│   └── audit.pub         # Public key for audit verification
└── .aegis_lock           # Lock file for concurrent access
```

### Path Traversal Protection

All file operations use secure path handling:

```python
import os
import re
from pathlib import Path

class SecurePath:
    """Secure path handling with traversal protection."""

    # Only allow alphanumeric, dash, underscore in path components
    SAFE_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')

    def __init__(self, base_path: Path):
        self.base = base_path.resolve()

    def validate_component(self, component: str) -> str:
        """Validate a single path component (e.g., run_id, test_id)."""
        if not component:
            raise PathValidationError("Empty path component")

        if not self.SAFE_PATTERN.match(component):
            raise PathValidationError(
                f"Invalid characters in path component: {component}"
            )

        if component in ('.', '..'):
            raise PathValidationError("Directory traversal attempt detected")

        if len(component) > 64:
            raise PathValidationError(f"Path component too long: {len(component)}")

        return component

    def safe_join(self, *components: str) -> Path:
        """Safely join path components with traversal protection."""
        validated = [self.validate_component(c) for c in components]
        result = self.base.joinpath(*validated).resolve()

        # Final check: must still be under base
        if not str(result).startswith(str(self.base)):
            raise PathValidationError(
                f"Path escapes base directory: {result}"
            )

        return result

    def safe_open(self, *components: str, mode: str = 'r') -> IO:
        """Safely open a file with path validation."""
        path = self.safe_join(*components)

        # Additional safety: no symlinks
        if path.is_symlink():
            raise PathValidationError(f"Symlinks not allowed: {path}")

        return open(path, mode)
```

### Encryption at Rest

Sensitive data is encrypted using Fernet (AES-128-CBC with HMAC):

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os

class DataEncryption:
    """Encryption at rest for sensitive data."""

    def __init__(self, key_path: Path, master_password: str = None):
        self.key_path = key_path
        self._fernet = self._load_or_create_key(master_password)

    def _load_or_create_key(self, master_password: str) -> Fernet:
        """Load existing key or create new one."""
        if self.key_path.exists():
            # Verify file permissions (must be 0600)
            mode = self.key_path.stat().st_mode & 0o777
            if mode != 0o600:
                raise SecurityError(
                    f"Key file has insecure permissions: {oct(mode)}"
                )
            key = self.key_path.read_bytes()
        else:
            # Generate new key
            if master_password:
                # Derive from password
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=480000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            else:
                key = Fernet.generate_key()

            # Save with secure permissions
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            self.key_path.touch(mode=0o600)
            self.key_path.write_bytes(key)

        return Fernet(key)

    def encrypt(self, data: str) -> str:
        """Encrypt string data, return base64-encoded ciphertext."""
        return self._fernet.encrypt(data.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt base64-encoded ciphertext to string."""
        return self._fernet.decrypt(ciphertext.encode()).decode()

    def encrypt_dict(self, data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """Encrypt specified fields in a dictionary."""
        result = data.copy()
        for field in fields:
            if field in result and result[field]:
                result[field] = self.encrypt(str(result[field]))
                result[f"{field}_encrypted"] = True
        return result

    def decrypt_dict(self, data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """Decrypt specified fields in a dictionary."""
        result = data.copy()
        for field in fields:
            if data.get(f"{field}_encrypted") and field in result:
                result[field] = self.decrypt(result[field])
                del result[f"{field}_encrypted"]
        return result
```

### Database Schema (Updated)

```sql
-- Principals table (authentication)
CREATE TABLE principals (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    roles TEXT NOT NULL,                  -- JSON array
    api_key_hash TEXT UNIQUE NOT NULL,    -- bcrypt hash (NOT reversible, includes salt)
    is_revoked INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_active DATETIME,
    created_by TEXT REFERENCES principals(id)
);

-- Scopes table
CREATE TABLE scopes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner TEXT NOT NULL REFERENCES principals(id),
    authorized_targets TEXT NOT NULL,     -- JSON array of TargetPattern
    time_window_start DATETIME,
    time_window_end DATETIME,
    max_requests INTEGER DEFAULT 1000,
    max_concurrency INTEGER DEFAULT 5,
    restrictions TEXT,                    -- JSON object
    approvals TEXT NOT NULL,              -- JSON array of Approval (signatures)
    min_approvals INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    status TEXT DEFAULT 'active',         -- active, expired, revoked
    CHECK (min_approvals >= 1)
);

-- Targets table
CREATE TABLE targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,                   -- http, openai, anthropic, local
    config_encrypted TEXT NOT NULL,       -- ENCRYPTED JSON: url, api_key, model, etc.
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT REFERENCES principals(id)
);

-- Runs table
CREATE TABLE runs (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL REFERENCES scopes(id),
    target_id TEXT NOT NULL REFERENCES targets(id),
    pack_id TEXT NOT NULL,
    pack_version TEXT NOT NULL,
    seed INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',        -- pending, running, completed, failed, aborted
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NOT NULL REFERENCES principals(id),
    started_at DATETIME,
    completed_at DATETIME,
    test_count INTEGER DEFAULT 0,
    passed_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    score_summary TEXT,                   -- JSON object
    artifacts_path TEXT,                  -- Validated path (no traversal)
    CHECK (id GLOB '[a-zA-Z0-9_-]*')      -- Path-safe characters only
);

-- Test Results table
CREATE TABLE test_results (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    test_case_id TEXT NOT NULL,
    status TEXT NOT NULL,                 -- passed, failed, error, skipped
    severity TEXT,
    susceptibility TEXT,
    observation TEXT,
    evidence_path TEXT,                   -- Validated path to evidence file
    started_at DATETIME,
    completed_at DATETIME,
    duration_ms INTEGER,
    CHECK (id GLOB '[a-zA-Z0-9_-]*')      -- Path-safe characters only
);

-- Audit Log table (append-only, signed)
CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    run_id TEXT,
    scope_id TEXT,
    principal_id TEXT NOT NULL,           -- Authenticated actor
    action TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL,                -- success, failure, error
    details TEXT,                         -- JSON object (redacted)
    previous_hash TEXT,                   -- Hash of previous entry
    entry_hash TEXT NOT NULL,             -- Hash of this entry
    signature TEXT NOT NULL               -- Ed25519 signature
);

-- Trigger to prevent audit log modification
CREATE TRIGGER prevent_audit_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Audit log entries cannot be modified');
END;

CREATE TRIGGER prevent_audit_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'Audit log entries cannot be deleted');
END;

-- Create indexes
CREATE INDEX idx_runs_scope ON runs(scope_id);
CREATE INDEX idx_runs_target ON runs(target_id);
CREATE INDEX idx_runs_status ON runs(status);
CREATE INDEX idx_runs_created_by ON runs(created_by);
CREATE INDEX idx_results_run ON test_results(run_id);
CREATE INDEX idx_audit_run ON audit_log(run_id);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_principal ON audit_log(principal_id);
CREATE INDEX idx_principals_key_hash ON principals(api_key_hash);
CREATE INDEX idx_scopes_owner ON scopes(owner);
```

### Repository Pattern (Secure)

```python
class Repository(ABC):
    """Abstract repository interface for pluggable storage."""

    @abstractmethod
    def save_scope(self, scope: Scope, principal: Principal) -> str: ...

    @abstractmethod
    def get_scope(self, scope_id: str, principal: Principal) -> Optional[Scope]: ...

    @abstractmethod
    def save_run(self, run: Run, principal: Principal) -> str: ...

    @abstractmethod
    def get_run(self, run_id: str, principal: Principal) -> Optional[Run]: ...

    @abstractmethod
    def list_runs(self, filters: RunFilters, principal: Principal) -> List[Run]: ...

    @abstractmethod
    def save_principal(self, principal: Principal, created_by: Principal) -> str: ...

    @abstractmethod
    def get_principal_by_key_hash(self, key_hash: str) -> Optional[Principal]: ...


class SQLiteRepository(Repository):
    """SQLite implementation of repository with security features.

    SECURITY WARNING: In production deployments, encryption MUST be enabled
    for storing sensitive data (API keys, target configs, evidence).

    Set AEGIS_REQUIRE_ENCRYPTION=1 environment variable to enforce encryption.
    """

    def __init__(
        self,
        db_path: str = "aegis_data/aegis.db",
        encryption: DataEncryption = None,
        require_encryption: bool = None
    ):
        self.db_path = db_path
        self.encryption = encryption
        self.secure_path = SecurePath(Path(db_path).parent)

        # Check encryption requirement
        require = require_encryption
        if require is None:
            require = os.environ.get("AEGIS_REQUIRE_ENCRYPTION", "0") == "1"

        if require and not encryption:
            raise SecurityError(
                "Encryption is required but not configured. "
                "Set encryption=DataEncryption(...) or disable requirement."
            )

        if not encryption:
            logger.warning(
                "SECURITY WARNING: Encryption is disabled. "
                "Sensitive data (API keys, credentials) will be stored in plaintext. "
                "Enable encryption for production deployments."
            )

        self._init_db()

    def _init_db(self):
        """Initialize database with schema."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        # Create tables from schema
        conn.executescript(SCHEMA_SQL)
        conn.close()

    def save_target(self, target: Target, principal: Principal) -> str:
        """Save target with encrypted config."""
        # Encrypt sensitive config fields
        config_str = json.dumps(target.config)
        if self.encryption:
            config_encrypted = self.encryption.encrypt(config_str)
        else:
            config_encrypted = config_str

        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """
            INSERT INTO targets (id, name, type, config_encrypted, created_by)
            VALUES (?, ?, ?, ?, ?)
            """,
            (target.id, target.name, target.type, config_encrypted, principal.id)
        )
        conn.commit()
        conn.close()
        return target.id

    def get_target(self, target_id: str, principal: Principal) -> Optional[Target]:
        """Get target with decrypted config."""
        # Validate target_id is path-safe
        self.secure_path.validate_component(target_id)

        conn = sqlite3.connect(self.db_path)
        row = conn.execute(
            "SELECT * FROM targets WHERE id = ?",
            (target_id,)
        ).fetchone()
        conn.close()

        if not row:
            return None

        # Decrypt config
        config_encrypted = row['config_encrypted']
        if self.encryption:
            config_str = self.encryption.decrypt(config_encrypted)
        else:
            config_str = config_encrypted

        return Target(
            id=row['id'],
            name=row['name'],
            type=row['type'],
            config=json.loads(config_str)
        )


class PostgresRepository(Repository):
    """PostgreSQL implementation for enterprise deployments."""
    pass  # Future implementation
```

### Artifact Storage (Secure)

```python
class ArtifactStore:
    """File-based artifact storage with path validation and optional encryption."""

    def __init__(
        self,
        base_path: str = "aegis_data/artifacts",
        encryption: DataEncryption = None,
        redaction: RedactionService = None
    ):
        self.base_path = Path(base_path)
        self.secure_path = SecurePath(self.base_path)
        self.encryption = encryption
        self.redaction = redaction or RedactionService()

    def store_evidence(
        self,
        run_id: str,
        test_id: str,
        evidence: Evidence
    ) -> str:
        """Store evidence as JSON file, return validated path."""
        # Validate path components (prevents traversal)
        self.secure_path.validate_component(run_id)
        self.secure_path.validate_component(test_id)

        # Create directory safely
        run_dir = self.secure_path.safe_join(run_id)
        run_dir.mkdir(parents=True, exist_ok=True)

        # Redact before storage
        evidence_dict = evidence.to_dict()
        redacted = self.redaction.redact_dict(evidence_dict, [
            'request', 'response', 'headers', 'body'
        ])

        # Optionally encrypt
        content = json.dumps(redacted, indent=2)
        if self.encryption:
            content = self.encryption.encrypt(content)

        # Write with secure path
        file_path = self.secure_path.safe_join(run_id, f"{test_id}.json")
        with open(file_path, 'w') as f:
            f.write(content)

        # Return relative path (no absolute paths in DB)
        return f"{run_id}/{test_id}.json"

    def retrieve_evidence(self, relative_path: str) -> Optional[Evidence]:
        """Retrieve evidence from validated path."""
        # Parse and validate path components
        parts = relative_path.split('/')
        if len(parts) != 2:
            raise PathValidationError(f"Invalid evidence path format: {relative_path}")

        run_id, filename = parts
        self.secure_path.validate_component(run_id)

        # Validate filename
        if not filename.endswith('.json'):
            raise PathValidationError("Evidence must be JSON file")
        test_id = filename[:-5]  # Remove .json
        self.secure_path.validate_component(test_id)

        # Read with secure path
        file_path = self.secure_path.safe_join(run_id, filename)
        if not file_path.exists():
            return None

        with open(file_path, 'r') as f:
            content = f.read()

        # Decrypt if encrypted
        if self.encryption:
            try:
                content = self.encryption.decrypt(content)
            except Exception:
                pass  # Not encrypted, use as-is

        return Evidence.from_dict(json.loads(content))

    def delete_run_artifacts(self, run_id: str) -> None:
        """Securely delete all artifacts for a run."""
        self.secure_path.validate_component(run_id)
        run_dir = self.secure_path.safe_join(run_id)

        if run_dir.exists():
            # Secure deletion: overwrite before delete
            for file in run_dir.iterdir():
                if file.is_file():
                    size = file.stat().st_size
                    with open(file, 'wb') as f:
                        f.write(os.urandom(size))  # Overwrite with random
                    file.unlink()
            run_dir.rmdir()
```

### Audit Log Integrity

```python
class AuditLogger:
    """Append-only audit log with hash chain and signatures."""

    def __init__(
        self,
        repository: Repository,
        signing_key: Ed25519PrivateKey,
        redaction: RedactionService = None
    ):
        self.repository = repository
        self.signing_key = signing_key
        self.redaction = redaction or RedactionService()
        self._last_hash = self._get_last_hash()

    def log(self, entry: AuditEntry) -> None:
        """Append signed entry to audit log."""
        # Redact details before logging
        if entry.details:
            entry.details = self.redaction.redact_dict(entry.details, list(entry.details.keys()))

        # Compute hash chain
        entry.previous_hash = self._last_hash
        entry_content = self._serialize_for_hash(entry)
        entry.entry_hash = hashlib.sha256(entry_content.encode()).hexdigest()

        # Sign the entry
        entry.signature = base64.b64encode(
            self.signing_key.sign(entry.entry_hash.encode())
        ).decode()

        self._last_hash = entry.entry_hash

        # Append to database
        self.repository.append_audit(entry)

    def _serialize_for_hash(self, entry: AuditEntry) -> str:
        """Deterministic serialization for hashing."""
        return (
            f"{entry.timestamp.isoformat()}|"
            f"{entry.principal_id}|"
            f"{entry.action}|"
            f"{entry.target or ''}|"
            f"{entry.outcome}|"
            f"{entry.previous_hash or ''}"
        )

    def verify_integrity(self, public_key: Ed25519PublicKey) -> Tuple[bool, List[str]]:
        """Verify hash chain and all signatures."""
        entries = self.repository.get_all_audit_entries()
        prev_hash = None
        errors = []

        for i, entry in enumerate(entries):
            # Verify chain
            if entry.previous_hash != prev_hash:
                errors.append(
                    f"Chain broken at entry {i}: "
                    f"expected {prev_hash}, got {entry.previous_hash}"
                )

            # Verify hash
            expected_hash = hashlib.sha256(
                self._serialize_for_hash(entry).encode()
            ).hexdigest()
            if entry.entry_hash != expected_hash:
                errors.append(
                    f"Hash mismatch at entry {i}: "
                    f"expected {expected_hash}, got {entry.entry_hash}"
                )

            # Verify signature
            try:
                public_key.verify(
                    base64.b64decode(entry.signature),
                    entry.entry_hash.encode()
                )
            except InvalidSignature:
                errors.append(f"Invalid signature at entry {i}")

            prev_hash = entry.entry_hash

        return len(errors) == 0, errors

    def export_for_compliance(
        self,
        start_date: datetime,
        end_date: datetime,
        format: str = "json"
    ) -> str:
        """Export audit log entries for compliance review."""
        entries = self.repository.get_audit_entries_in_range(start_date, end_date)

        if format == "json":
            return json.dumps([e.to_dict() for e in entries], indent=2)
        elif format == "csv":
            # CSV format for spreadsheet import
            lines = ["timestamp,principal_id,action,target,outcome,entry_hash"]
            for e in entries:
                lines.append(
                    f"{e.timestamp},{e.principal_id},{e.action},"
                    f"{e.target or ''},{e.outcome},{e.entry_hash}"
                )
            return "\n".join(lines)
        else:
            raise ValueError(f"Unknown format: {format}")
```

## Consequences

**Positive:**
- Zero external dependencies (SQLite built into Python)
- Single file backup/restore
- Full SQL query capability
- Hash chain provides tamper evidence
- **Path traversal attacks prevented**
- **Sensitive data encrypted at rest**
- **Audit log immutable via triggers**

**Negative:**
- SQLite has concurrency limitations
- Need migration strategy for schema changes
- Artifact storage can grow large
- Encryption adds slight performance overhead

## Migration Path

1. Start with SQLite (single-user, self-hosted)
2. Add PostgreSQL adapter for team deployments
3. Add S3/GCS adapter for artifact storage
4. All via repository interface - no code changes needed

## Security Guarantees

1. **Path traversal protection**: All paths validated before use
2. **Encryption at rest**: Target configs and optionally evidence
3. **Audit immutability**: Database triggers prevent modification
4. **Signed audit entries**: Cryptographic proof of integrity
5. **Secure key storage**: Key files with 0600 permissions
6. **No symlink following**: Symlinks rejected in artifact paths
