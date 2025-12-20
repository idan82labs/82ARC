"""Core engine components for Aegis."""

from aegis.core.engine import AegisEngine
from aegis.core.models import (
    Scope,
    Target,
    Run,
    TestCase,
    TestResult,
    Evidence,
    Principal,
    Approval,
    TargetPattern,
    TimeWindow,
    ScopeRestrictions,
    RunStatus,
    TestStatus,
    Severity,
    ScoreSummary,
)
from aegis.core.auth import AuthService, TrustedKeyStore
from aegis.core.repository import SQLiteRepository, Repository
from aegis.core.redaction import RedactionService
from aegis.core.audit import AuditLogger, AuditEntry
from aegis.core.storage import SecurePath, DataEncryption
from aegis.core.pack_loader import Pack, TestSuite, SecurePackLoader, ExecutorRegistry

__all__ = [
    # Engine
    "AegisEngine",
    # Models
    "Scope",
    "Target",
    "Run",
    "TestCase",
    "TestResult",
    "Evidence",
    "Principal",
    "Approval",
    "TargetPattern",
    "TimeWindow",
    "ScopeRestrictions",
    "RunStatus",
    "TestStatus",
    "Severity",
    "ScoreSummary",
    # Auth
    "AuthService",
    "TrustedKeyStore",
    # Repository
    "Repository",
    "SQLiteRepository",
    # Services
    "RedactionService",
    "AuditLogger",
    "AuditEntry",
    # Storage
    "SecurePath",
    "DataEncryption",
    # Packs
    "Pack",
    "TestSuite",
    "SecurePackLoader",
    "ExecutorRegistry",
]
