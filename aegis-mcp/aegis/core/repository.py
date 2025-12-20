"""Repository pattern for persistent storage.

Implements:
- SQLite repository with encryption support
- Abstract interface for pluggable backends
"""

import json
import logging
import os
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis.core.exceptions import (
    RunAlreadyExistsError,
    RunNotFoundError,
    ScopeNotFoundError,
    SecurityError,
)
from aegis.core.models import (
    Principal,
    Run,
    Scope,
    Target,
    TestResult,
    ScoreSummary,
    TargetPattern,
    TimeWindow,
    ScopeRestrictions,
    Approval,
)
from aegis.core.storage import DataEncryption, SecurePath
from aegis.core.audit import AuditEntry

logger = logging.getLogger(__name__)


# Database schema
SCHEMA_SQL = """
-- Principals table (authentication)
CREATE TABLE IF NOT EXISTS principals (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    roles TEXT NOT NULL,
    api_key_hash TEXT UNIQUE NOT NULL,
    public_key BLOB,
    public_key_fingerprint TEXT,
    is_revoked INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_active TEXT,
    created_by TEXT REFERENCES principals(id)
);

-- Scopes table
CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner TEXT NOT NULL REFERENCES principals(id),
    authorized_targets TEXT NOT NULL,
    time_window TEXT NOT NULL,
    max_requests INTEGER DEFAULT 1000,
    max_concurrency INTEGER DEFAULT 5,
    restrictions TEXT,
    approvals TEXT NOT NULL,
    min_approvals INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL,
    status TEXT DEFAULT 'active',
    requests_used INTEGER DEFAULT 0,
    CHECK (min_approvals >= 1)
);

-- Targets table
CREATE TABLE IF NOT EXISTS targets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    config_encrypted TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT REFERENCES principals(id)
);

-- Runs table
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    scope_id TEXT NOT NULL REFERENCES scopes(id),
    target_id TEXT NOT NULL REFERENCES targets(id),
    pack_id TEXT NOT NULL,
    pack_version TEXT NOT NULL,
    seed INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT NOT NULL REFERENCES principals(id),
    started_at TEXT,
    completed_at TEXT,
    test_count INTEGER DEFAULT 0,
    passed_count INTEGER DEFAULT 0,
    failed_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    score_summary TEXT,
    artifacts_path TEXT
);

-- Test Results table
CREATE TABLE IF NOT EXISTS test_results (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),
    test_case_id TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT,
    susceptibility TEXT,
    observation TEXT,
    evidence_path TEXT,
    started_at TEXT,
    completed_at TEXT,
    duration_ms INTEGER
);

-- Audit Log table (append-only, signed)
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
    run_id TEXT,
    scope_id TEXT,
    principal_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL,
    details TEXT,
    previous_hash TEXT,
    entry_hash TEXT NOT NULL,
    signature TEXT NOT NULL
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_runs_scope ON runs(scope_id);
CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target_id);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
CREATE INDEX IF NOT EXISTS idx_runs_created_by ON runs(created_by);
CREATE INDEX IF NOT EXISTS idx_results_run ON test_results(run_id);
CREATE INDEX IF NOT EXISTS idx_audit_run ON audit_log(run_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_log(principal_id);
CREATE INDEX IF NOT EXISTS idx_scopes_owner ON scopes(owner);
"""


class Repository(ABC):
    """Abstract repository interface for pluggable storage."""

    # Principal operations
    @abstractmethod
    def save_principal(self, principal: Principal) -> str:
        ...

    @abstractmethod
    def get_principal(self, principal_id: str) -> Optional[Principal]:
        ...

    @abstractmethod
    def get_all_principals(self) -> List[Principal]:
        ...

    @abstractmethod
    def update_last_active(self, principal_id: str) -> None:
        ...

    @abstractmethod
    def update_principal_key_hash(self, principal_id: str, key_hash: str) -> None:
        ...

    @abstractmethod
    def update_principal_public_key(
        self,
        principal_id: str,
        public_key: Optional[bytes],
        fingerprint: Optional[str],
    ) -> None:
        ...

    # Scope operations
    @abstractmethod
    def save_scope(self, scope: Scope) -> str:
        ...

    @abstractmethod
    def get_scope(self, scope_id: str) -> Optional[Scope]:
        ...

    @abstractmethod
    def list_scopes(self, owner: Optional[str] = None) -> List[Scope]:
        ...

    @abstractmethod
    def update_scope_requests(self, scope_id: str, used: int) -> None:
        ...

    # Target operations
    @abstractmethod
    def save_target(self, target: Target) -> str:
        ...

    @abstractmethod
    def get_target(self, target_id: str) -> Optional[Target]:
        ...

    @abstractmethod
    def list_targets(self) -> List[Target]:
        ...

    # Run operations
    @abstractmethod
    def save_run(self, run: Run) -> str:
        ...

    @abstractmethod
    def get_run(self, run_id: str) -> Optional[Run]:
        ...

    @abstractmethod
    def list_runs(
        self,
        scope_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Run]:
        ...

    @abstractmethod
    def update_run_status(
        self,
        run_id: str,
        status: str,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
    ) -> None:
        ...

    @abstractmethod
    def update_run_counts(
        self,
        run_id: str,
        test_count: int,
        passed_count: int,
        failed_count: int,
        error_count: int,
    ) -> None:
        ...

    @abstractmethod
    def update_run_summary(self, run_id: str, summary: ScoreSummary) -> None:
        ...

    # Test result operations
    @abstractmethod
    def save_test_result(self, result: TestResult) -> str:
        ...

    @abstractmethod
    def get_test_results(self, run_id: str) -> List[TestResult]:
        ...

    # Audit operations
    @abstractmethod
    def append_audit(self, entry: AuditEntry) -> None:
        ...

    @abstractmethod
    def get_last_audit_entry(self) -> Optional[AuditEntry]:
        ...

    @abstractmethod
    def get_all_audit_entries(self) -> List[AuditEntry]:
        ...

    @abstractmethod
    def get_audit_entries_in_range(
        self, start: datetime, end: datetime
    ) -> List[AuditEntry]:
        ...

    @abstractmethod
    def get_audit_entries_for_run(self, run_id: str) -> List[AuditEntry]:
        ...

    @abstractmethod
    def get_audit_entries_for_principal(
        self, principal_id: str, limit: int
    ) -> List[AuditEntry]:
        ...


class SQLiteRepository(Repository):
    """SQLite implementation of repository with security features."""

    def __init__(
        self,
        db_path: str = "aegis_data/aegis.db",
        encryption: Optional[DataEncryption] = None,
        require_encryption: Optional[bool] = None,
    ):
        """Initialize SQLite repository.

        Args:
            db_path: Path to SQLite database file
            encryption: Optional encryption for sensitive fields
            require_encryption: If True, raise error if encryption not provided
        """
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
                "Sensitive data will be stored in plaintext. "
                "Enable encryption for production deployments."
            )

        self._init_db()

    def _init_db(self):
        """Initialize database with schema."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        conn.close()
        logger.info(f"Initialized database at {self.db_path}")

    def _get_conn(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    # ==================== Principal Operations ====================

    def save_principal(self, principal: Principal) -> str:
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO principals
                (id, name, email, roles, api_key_hash, public_key,
                 public_key_fingerprint, is_revoked, created_at, last_active, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    principal.id,
                    principal.name,
                    principal.email,
                    json.dumps(principal.roles),
                    principal.api_key_hash,
                    principal.public_key,
                    principal.public_key_fingerprint,
                    1 if principal.is_revoked else 0,
                    principal.created_at.isoformat(),
                    principal.last_active.isoformat() if principal.last_active else None,
                    principal.created_by,
                ),
            )
            conn.commit()
            return principal.id
        finally:
            conn.close()

    def get_principal(self, principal_id: str) -> Optional[Principal]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM principals WHERE id = ?", (principal_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_principal(row)
        finally:
            conn.close()

    def get_all_principals(self) -> List[Principal]:
        conn = self._get_conn()
        try:
            rows = conn.execute("SELECT * FROM principals WHERE is_revoked = 0").fetchall()
            return [self._row_to_principal(row) for row in rows]
        finally:
            conn.close()

    def _row_to_principal(self, row: sqlite3.Row) -> Principal:
        return Principal(
            id=row["id"],
            name=row["name"],
            email=row["email"],
            roles=json.loads(row["roles"]),
            api_key_hash=row["api_key_hash"],
            public_key=row["public_key"],
            public_key_fingerprint=row["public_key_fingerprint"],
            is_revoked=bool(row["is_revoked"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            last_active=datetime.fromisoformat(row["last_active"])
            if row["last_active"]
            else None,
            created_by=row["created_by"],
        )

    def update_last_active(self, principal_id: str) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE principals SET last_active = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), principal_id),
            )
            conn.commit()
        finally:
            conn.close()

    def update_principal_key_hash(self, principal_id: str, key_hash: str) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE principals SET api_key_hash = ? WHERE id = ?",
                (key_hash, principal_id),
            )
            conn.commit()
        finally:
            conn.close()

    def update_principal_public_key(
        self,
        principal_id: str,
        public_key: Optional[bytes],
        fingerprint: Optional[str],
    ) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                """UPDATE principals
                   SET public_key = ?, public_key_fingerprint = ?
                   WHERE id = ?""",
                (public_key, fingerprint, principal_id),
            )
            conn.commit()
        finally:
            conn.close()

    # ==================== Scope Operations ====================

    def save_scope(self, scope: Scope) -> str:
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO scopes
                (id, name, owner, authorized_targets, time_window, max_requests,
                 max_concurrency, restrictions, approvals, min_approvals,
                 created_at, expires_at, status, requests_used)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope.id,
                    scope.name,
                    scope.owner,
                    json.dumps([t.to_dict() for t in scope.authorized_targets]),
                    json.dumps(scope.time_window.to_dict()),
                    scope.max_requests,
                    scope.max_concurrency,
                    json.dumps(scope.restrictions.to_dict())
                    if scope.restrictions
                    else None,
                    json.dumps([a.to_dict() for a in scope.approvals]),
                    scope.min_approvals,
                    scope.created_at.isoformat(),
                    scope.expires_at.isoformat(),
                    scope.status,
                    scope.requests_used,
                ),
            )
            conn.commit()
            return scope.id
        finally:
            conn.close()

    def get_scope(self, scope_id: str) -> Optional[Scope]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM scopes WHERE id = ?", (scope_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_scope(row)
        finally:
            conn.close()

    def list_scopes(self, owner: Optional[str] = None) -> List[Scope]:
        conn = self._get_conn()
        try:
            if owner:
                rows = conn.execute(
                    "SELECT * FROM scopes WHERE owner = ?", (owner,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM scopes").fetchall()
            return [self._row_to_scope(row) for row in rows]
        finally:
            conn.close()

    def _row_to_scope(self, row: sqlite3.Row) -> Scope:
        targets_data = json.loads(row["authorized_targets"])
        time_window_data = json.loads(row["time_window"])
        restrictions_data = json.loads(row["restrictions"]) if row["restrictions"] else None
        approvals_data = json.loads(row["approvals"])

        return Scope(
            id=row["id"],
            name=row["name"],
            owner=row["owner"],
            authorized_targets=[TargetPattern.from_dict(t) for t in targets_data],
            time_window=TimeWindow.from_dict(time_window_data),
            max_requests=row["max_requests"],
            max_concurrency=row["max_concurrency"],
            restrictions=ScopeRestrictions.from_dict(restrictions_data)
            if restrictions_data
            else None,
            approvals=[Approval.from_dict(a) for a in approvals_data],
            min_approvals=row["min_approvals"],
            created_at=datetime.fromisoformat(row["created_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]),
            status=row["status"],
            requests_used=row["requests_used"],
        )

    def update_scope_requests(self, scope_id: str, used: int) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE scopes SET requests_used = ? WHERE id = ?",
                (used, scope_id),
            )
            conn.commit()
        finally:
            conn.close()

    # ==================== Target Operations ====================

    def save_target(self, target: Target) -> str:
        conn = self._get_conn()
        try:
            config_str = json.dumps(target.config)
            if self.encryption:
                config_encrypted = self.encryption.encrypt(config_str)
            else:
                config_encrypted = config_str

            conn.execute(
                """
                INSERT INTO targets (id, name, type, config_encrypted, created_at, updated_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target.id,
                    target.name,
                    target.type,
                    config_encrypted,
                    target.created_at.isoformat(),
                    target.updated_at.isoformat(),
                    target.created_by,
                ),
            )
            conn.commit()
            return target.id
        finally:
            conn.close()

    def get_target(self, target_id: str) -> Optional[Target]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM targets WHERE id = ?", (target_id,)
            ).fetchone()
            if not row:
                return None
            return self._row_to_target(row)
        finally:
            conn.close()

    def list_targets(self) -> List[Target]:
        conn = self._get_conn()
        try:
            rows = conn.execute("SELECT * FROM targets").fetchall()
            return [self._row_to_target(row) for row in rows]
        finally:
            conn.close()

    def _row_to_target(self, row: sqlite3.Row) -> Target:
        config_encrypted = row["config_encrypted"]
        if self.encryption and self.encryption.is_encrypted(config_encrypted):
            config_str = self.encryption.decrypt(config_encrypted)
        else:
            config_str = config_encrypted

        return Target(
            id=row["id"],
            name=row["name"],
            type=row["type"],
            config=json.loads(config_str),
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            created_by=row["created_by"],
        )

    # ==================== Run Operations ====================

    def save_run(self, run: Run) -> str:
        conn = self._get_conn()
        try:
            # Check for duplicate
            existing = conn.execute(
                "SELECT id FROM runs WHERE id = ?", (run.id,)
            ).fetchone()
            if existing:
                raise RunAlreadyExistsError(f"Run {run.id} already exists")

            conn.execute(
                """
                INSERT INTO runs
                (id, scope_id, target_id, pack_id, pack_version, seed, status,
                 created_at, created_by, started_at, completed_at, test_count,
                 passed_count, failed_count, error_count, score_summary, artifacts_path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run.id,
                    run.scope_id,
                    run.target_id,
                    run.pack_id,
                    run.pack_version,
                    run.seed,
                    run.status,
                    run.created_at.isoformat(),
                    run.created_by,
                    run.started_at.isoformat() if run.started_at else None,
                    run.completed_at.isoformat() if run.completed_at else None,
                    run.test_count,
                    run.passed_count,
                    run.failed_count,
                    run.error_count,
                    json.dumps(run.score_summary.to_dict())
                    if run.score_summary
                    else None,
                    run.artifacts_path,
                ),
            )
            conn.commit()
            return run.id
        finally:
            conn.close()

    def get_run(self, run_id: str) -> Optional[Run]:
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
            if not row:
                return None
            return self._row_to_run(row)
        finally:
            conn.close()

    def list_runs(
        self,
        scope_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Run]:
        conn = self._get_conn()
        try:
            query = "SELECT * FROM runs WHERE 1=1"
            params = []
            if scope_id:
                query += " AND scope_id = ?"
                params.append(scope_id)
            if status:
                query += " AND status = ?"
                params.append(status)
            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_run(row) for row in rows]
        finally:
            conn.close()

    def _row_to_run(self, row: sqlite3.Row) -> Run:
        return Run(
            id=row["id"],
            scope_id=row["scope_id"],
            target_id=row["target_id"],
            pack_id=row["pack_id"],
            pack_version=row["pack_version"],
            seed=row["seed"],
            status=row["status"],
            created_at=datetime.fromisoformat(row["created_at"]),
            created_by=row["created_by"],
            started_at=datetime.fromisoformat(row["started_at"])
            if row["started_at"]
            else None,
            completed_at=datetime.fromisoformat(row["completed_at"])
            if row["completed_at"]
            else None,
            test_count=row["test_count"],
            passed_count=row["passed_count"],
            failed_count=row["failed_count"],
            error_count=row["error_count"],
            score_summary=ScoreSummary.from_dict(json.loads(row["score_summary"]))
            if row["score_summary"]
            else None,
            artifacts_path=row["artifacts_path"],
        )

    def update_run_status(
        self,
        run_id: str,
        status: str,
        started_at: Optional[datetime] = None,
        completed_at: Optional[datetime] = None,
    ) -> None:
        conn = self._get_conn()
        try:
            if started_at and completed_at:
                conn.execute(
                    "UPDATE runs SET status = ?, started_at = ?, completed_at = ? WHERE id = ?",
                    (status, started_at.isoformat(), completed_at.isoformat(), run_id),
                )
            elif started_at:
                conn.execute(
                    "UPDATE runs SET status = ?, started_at = ? WHERE id = ?",
                    (status, started_at.isoformat(), run_id),
                )
            elif completed_at:
                conn.execute(
                    "UPDATE runs SET status = ?, completed_at = ? WHERE id = ?",
                    (status, completed_at.isoformat(), run_id),
                )
            else:
                conn.execute(
                    "UPDATE runs SET status = ? WHERE id = ?",
                    (status, run_id),
                )
            conn.commit()
        finally:
            conn.close()

    def update_run_counts(
        self,
        run_id: str,
        test_count: int,
        passed_count: int,
        failed_count: int,
        error_count: int,
    ) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                """UPDATE runs
                   SET test_count = ?, passed_count = ?, failed_count = ?, error_count = ?
                   WHERE id = ?""",
                (test_count, passed_count, failed_count, error_count, run_id),
            )
            conn.commit()
        finally:
            conn.close()

    def update_run_summary(self, run_id: str, summary: ScoreSummary) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                "UPDATE runs SET score_summary = ? WHERE id = ?",
                (json.dumps(summary.to_dict()), run_id),
            )
            conn.commit()
        finally:
            conn.close()

    # ==================== Test Result Operations ====================

    def save_test_result(self, result: TestResult) -> str:
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO test_results
                (id, run_id, test_case_id, status, severity, susceptibility,
                 observation, evidence_path, started_at, completed_at, duration_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.id,
                    result.run_id,
                    result.test_case_id,
                    result.status,
                    result.severity,
                    result.susceptibility,
                    result.observation,
                    result.evidence_path,
                    result.started_at.isoformat() if result.started_at else None,
                    result.completed_at.isoformat() if result.completed_at else None,
                    result.duration_ms,
                ),
            )
            conn.commit()
            return result.id
        finally:
            conn.close()

    def get_test_results(self, run_id: str) -> List[TestResult]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM test_results WHERE run_id = ?", (run_id,)
            ).fetchall()
            return [
                TestResult(
                    id=row["id"],
                    run_id=row["run_id"],
                    test_case_id=row["test_case_id"],
                    status=row["status"],
                    severity=row["severity"],
                    susceptibility=row["susceptibility"],
                    observation=row["observation"],
                    evidence_path=row["evidence_path"],
                    started_at=datetime.fromisoformat(row["started_at"])
                    if row["started_at"]
                    else None,
                    completed_at=datetime.fromisoformat(row["completed_at"])
                    if row["completed_at"]
                    else None,
                    duration_ms=row["duration_ms"],
                )
                for row in rows
            ]
        finally:
            conn.close()

    # ==================== Audit Operations ====================

    def append_audit(self, entry: AuditEntry) -> None:
        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO audit_log
                (id, timestamp, run_id, scope_id, principal_id, action, target,
                 outcome, details, previous_hash, entry_hash, signature)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.id,
                    entry.timestamp.isoformat(),
                    entry.run_id,
                    entry.scope_id,
                    entry.principal_id,
                    entry.action,
                    entry.target,
                    entry.outcome,
                    json.dumps(entry.details) if entry.details else None,
                    entry.previous_hash,
                    entry.entry_hash,
                    entry.signature,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def get_last_audit_entry(self) -> Optional[AuditEntry]:
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM audit_log ORDER BY rowid DESC LIMIT 1"
            ).fetchone()
            if not row:
                return None
            return self._row_to_audit_entry(row)
        finally:
            conn.close()

    def get_all_audit_entries(self) -> List[AuditEntry]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY rowid ASC"
            ).fetchall()
            return [self._row_to_audit_entry(row) for row in rows]
        finally:
            conn.close()

    def get_audit_entries_in_range(
        self, start: datetime, end: datetime
    ) -> List[AuditEntry]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT * FROM audit_log
                   WHERE timestamp >= ? AND timestamp <= ?
                   ORDER BY rowid ASC""",
                (start.isoformat(), end.isoformat()),
            ).fetchall()
            return [self._row_to_audit_entry(row) for row in rows]
        finally:
            conn.close()

    def get_audit_entries_for_run(self, run_id: str) -> List[AuditEntry]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM audit_log WHERE run_id = ? ORDER BY rowid ASC",
                (run_id,),
            ).fetchall()
            return [self._row_to_audit_entry(row) for row in rows]
        finally:
            conn.close()

    def get_audit_entries_for_principal(
        self, principal_id: str, limit: int
    ) -> List[AuditEntry]:
        conn = self._get_conn()
        try:
            rows = conn.execute(
                """SELECT * FROM audit_log
                   WHERE principal_id = ?
                   ORDER BY rowid DESC LIMIT ?""",
                (principal_id, limit),
            ).fetchall()
            return [self._row_to_audit_entry(row) for row in rows]
        finally:
            conn.close()

    def _row_to_audit_entry(self, row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            run_id=row["run_id"],
            scope_id=row["scope_id"],
            principal_id=row["principal_id"],
            action=row["action"],
            target=row["target"],
            outcome=row["outcome"],
            details=json.loads(row["details"]) if row["details"] else None,
            previous_hash=row["previous_hash"],
            entry_hash=row["entry_hash"],
            signature=row["signature"],
        )
