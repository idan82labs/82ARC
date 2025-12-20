"""Core data models for Aegis.

All models are immutable dataclasses with validation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature


class RunStatus(str, Enum):
    """Status of a test run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class TestStatus(str, Enum):
    """Status of a single test."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"


class Severity(str, Enum):
    """Severity levels for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Susceptibility(str, Enum):
    """Susceptibility levels for test results."""

    NONE = "none"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


@dataclass(frozen=True)
class TimeWindow:
    """Time window for scope validity."""

    start: datetime
    end: datetime

    def is_active(self) -> bool:
        """Check if current time is within window."""
        now = datetime.utcnow()
        return self.start <= now <= self.end

    def to_dict(self) -> Dict[str, str]:
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> TimeWindow:
        return cls(
            start=datetime.fromisoformat(data["start"]),
            end=datetime.fromisoformat(data["end"]),
        )


@dataclass(frozen=True)
class TargetPattern:
    """Strict target matching pattern."""

    type: str  # "exact", "domain", "cidr", "regex"
    value: str
    ports: tuple = field(default_factory=tuple)  # Empty = all ports
    protocols: tuple = field(default_factory=lambda: ("https",))

    def __post_init__(self):
        if self.type not in ("exact", "domain", "cidr", "regex"):
            raise ValueError(f"Invalid pattern type: {self.type}")

    def matches(self, target_url: str) -> bool:
        """Strict pattern matching with explicit rules."""
        parsed = urlparse(target_url)

        # Protocol check
        if self.protocols and parsed.scheme not in self.protocols:
            return False

        # Port check
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if self.ports and port not in self.ports:
            return False

        hostname = parsed.hostname or ""

        # Host matching based on type
        if self.type == "exact":
            return parsed.netloc == self.value
        elif self.type == "domain":
            if self.value.startswith("*."):
                domain = self.value[2:]
                return hostname.endswith(f".{domain}")
            return hostname == self.value
        elif self.type == "cidr":
            try:
                network = ipaddress.ip_network(self.value)
                ip = ipaddress.ip_address(hostname)
                return ip in network
            except ValueError:
                return False
        elif self.type == "regex":
            return bool(re.fullmatch(self.value, hostname))
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "ports": list(self.ports),
            "protocols": list(self.protocols),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TargetPattern:
        return cls(
            type=data["type"],
            value=data["value"],
            ports=tuple(data.get("ports", [])),
            protocols=tuple(data.get("protocols", ["https"])),
        )


@dataclass(frozen=True)
class ScopeRestrictions:
    """Restrictions on what can be tested."""

    blocked_categories: tuple = field(default_factory=tuple)
    blocked_test_ids: tuple = field(default_factory=tuple)
    max_severity: Optional[str] = None
    require_confirmation_above: Optional[str] = None

    def blocks(self, test_case: "TestCase") -> bool:
        """Check if test case is blocked by restrictions."""
        if test_case.id in self.blocked_test_ids:
            return True
        if test_case.category in self.blocked_categories:
            return True
        if self.max_severity:
            severity_order = ["info", "low", "medium", "high", "critical"]
            if severity_order.index(test_case.severity) > severity_order.index(
                self.max_severity
            ):
                return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "blocked_categories": list(self.blocked_categories),
            "blocked_test_ids": list(self.blocked_test_ids),
            "max_severity": self.max_severity,
            "require_confirmation_above": self.require_confirmation_above,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScopeRestrictions:
        return cls(
            blocked_categories=tuple(data.get("blocked_categories", [])),
            blocked_test_ids=tuple(data.get("blocked_test_ids", [])),
            max_severity=data.get("max_severity"),
            require_confirmation_above=data.get("require_confirmation_above"),
        )


@dataclass
class Principal:
    """Authenticated identity for all operations."""

    id: str
    name: str
    email: str
    roles: List[str]
    api_key_hash: str  # bcrypt hash
    public_key: Optional[bytes] = None  # Ed25519 public key
    public_key_fingerprint: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_active: Optional[datetime] = None
    is_revoked: bool = False
    created_by: Optional[str] = None

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def is_admin(self) -> bool:
        return "admin" in self.roles

    def is_operator(self) -> bool:
        return "operator" in self.roles or "admin" in self.roles

    def is_auditor(self) -> bool:
        return "auditor" in self.roles

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "roles": self.roles,
            "api_key_hash": self.api_key_hash,
            "public_key": base64.b64encode(self.public_key).decode()
            if self.public_key
            else None,
            "public_key_fingerprint": self.public_key_fingerprint,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat() if self.last_active else None,
            "is_revoked": self.is_revoked,
            "created_by": self.created_by,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Principal:
        return cls(
            id=data["id"],
            name=data["name"],
            email=data["email"],
            roles=data["roles"],
            api_key_hash=data["api_key_hash"],
            public_key=base64.b64decode(data["public_key"])
            if data.get("public_key")
            else None,
            public_key_fingerprint=data.get("public_key_fingerprint"),
            created_at=datetime.fromisoformat(data["created_at"]),
            last_active=datetime.fromisoformat(data["last_active"])
            if data.get("last_active")
            else None,
            is_revoked=data.get("is_revoked", False),
            created_by=data.get("created_by"),
        )


@dataclass
class Approval:
    """Cryptographic approval signature using Ed25519."""

    approver_id: str
    approver_email: str
    timestamp: datetime
    signature: str  # Base64-encoded Ed25519 signature
    public_key_fingerprint: str

    def verify(self, scope_hash: str, public_key: Ed25519PublicKey) -> bool:
        """Verify approval signature against scope hash."""
        try:
            public_key.verify(
                base64.b64decode(self.signature), scope_hash.encode()
            )
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def sign(scope_hash: str, private_key: Ed25519PrivateKey) -> str:
        """Sign a scope hash with Ed25519 private key."""
        signature = private_key.sign(scope_hash.encode())
        return base64.b64encode(signature).decode()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approver_id": self.approver_id,
            "approver_email": self.approver_email,
            "timestamp": self.timestamp.isoformat(),
            "signature": self.signature,
            "public_key_fingerprint": self.public_key_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Approval:
        return cls(
            approver_id=data["approver_id"],
            approver_email=data["approver_email"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            signature=data["signature"],
            public_key_fingerprint=data["public_key_fingerprint"],
        )


@dataclass
class Scope:
    """Defines authorized testing boundaries."""

    id: str
    name: str
    owner: str
    authorized_targets: List[TargetPattern]
    time_window: TimeWindow
    max_requests: int = 1000
    max_concurrency: int = 5
    restrictions: Optional[ScopeRestrictions] = None
    approvals: List[Approval] = field(default_factory=list)
    min_approvals: int = 1
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=datetime.utcnow)
    status: str = "active"
    requests_used: int = 0

    @property
    def requests_remaining(self) -> int:
        return max(0, self.max_requests - self.requests_used)

    def allows_target(self, target_url: str) -> bool:
        """Check if target URL is allowed by any pattern."""
        return any(p.matches(target_url) for p in self.authorized_targets)

    def compute_hash(self) -> str:
        """Compute cryptographic hash of all authorization-relevant fields."""
        hash_content = json.dumps(
            {
                "id": self.id,
                "name": self.name,
                "owner": self.owner,
                "created_at": self.created_at.isoformat(),
                "authorized_targets": [
                    {
                        "type": t.type,
                        "value": t.value,
                        "ports": sorted(t.ports),
                        "protocols": sorted(t.protocols),
                    }
                    for t in sorted(self.authorized_targets, key=lambda x: x.value)
                ],
                "time_window_start": self.time_window.start.isoformat(),
                "time_window_end": self.time_window.end.isoformat(),
                "max_requests": self.max_requests,
                "max_concurrency": self.max_concurrency,
                "restrictions": self.restrictions.to_dict()
                if self.restrictions
                else None,
                "min_approvals": self.min_approvals,
                "expires_at": self.expires_at.isoformat(),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(hash_content.encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "owner": self.owner,
            "authorized_targets": [t.to_dict() for t in self.authorized_targets],
            "time_window": self.time_window.to_dict(),
            "max_requests": self.max_requests,
            "max_concurrency": self.max_concurrency,
            "restrictions": self.restrictions.to_dict() if self.restrictions else None,
            "approvals": [a.to_dict() for a in self.approvals],
            "min_approvals": self.min_approvals,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "status": self.status,
            "requests_used": self.requests_used,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Scope:
        return cls(
            id=data["id"],
            name=data["name"],
            owner=data["owner"],
            authorized_targets=[
                TargetPattern.from_dict(t) for t in data["authorized_targets"]
            ],
            time_window=TimeWindow.from_dict(data["time_window"]),
            max_requests=data.get("max_requests", 1000),
            max_concurrency=data.get("max_concurrency", 5),
            restrictions=ScopeRestrictions.from_dict(data["restrictions"])
            if data.get("restrictions")
            else None,
            approvals=[Approval.from_dict(a) for a in data.get("approvals", [])],
            min_approvals=data.get("min_approvals", 1),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            status=data.get("status", "active"),
            requests_used=data.get("requests_used", 0),
        )


@dataclass
class Target:
    """AI system under test."""

    id: str
    name: str
    type: str  # "http", "openai", "anthropic", "local"
    config: Dict[str, Any]  # URL, API key ref, model, etc.
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None

    @property
    def url(self) -> Optional[str]:
        return self.config.get("url")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "type": self.type,
            "config": self.config,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Target:
        return cls(
            id=data["id"],
            name=data["name"],
            type=data["type"],
            config=data["config"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            created_by=data.get("created_by"),
        )


@dataclass
class Evidence:
    """Captured request/response transcript."""

    request: str
    response: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    headers: Optional[Dict[str, str]] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request": self.request,
            "response": self.response,
            "timestamp": self.timestamp.isoformat(),
            "headers": self.headers,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Evidence:
        return cls(
            request=data["request"],
            response=data["response"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            headers=data.get("headers"),
            metadata=data.get("metadata"),
        )


@dataclass
class DetectionConfig:
    """Declarative detection configuration."""

    type: str  # "pattern_match", "semantic_analysis", "custom_metric"
    failure_patterns: Optional[List[str]] = None
    success_patterns: Optional[List[str]] = None
    analyzer: Optional[str] = None
    failure_threshold: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "failure_patterns": self.failure_patterns,
            "success_patterns": self.success_patterns,
            "analyzer": self.analyzer,
            "failure_threshold": self.failure_threshold,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DetectionConfig:
        return cls(
            type=data["type"],
            failure_patterns=data.get("failure_patterns"),
            success_patterns=data.get("success_patterns"),
            analyzer=data.get("analyzer"),
            failure_threshold=data.get("failure_threshold"),
        )


@dataclass
class TestCase:
    """Test case definition - data only, no code."""

    id: str
    name: str
    description: str
    category: str
    owasp_llm: List[str]
    mitre_atlas: List[str]
    input_template: str
    variables: Dict[str, Any]
    detection: DetectionConfig
    severity: str
    confidence_threshold: float = 0.8
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "owasp_llm": self.owasp_llm,
            "mitre_atlas": self.mitre_atlas,
            "input_template": self.input_template,
            "variables": self.variables,
            "detection": self.detection.to_dict(),
            "severity": self.severity,
            "confidence_threshold": self.confidence_threshold,
            "remediation": self.remediation,
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TestCase:
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            category=data["category"],
            owasp_llm=data.get("owasp_llm", []),
            mitre_atlas=data.get("mitre_atlas", []),
            input_template=data["input_template"],
            variables=data.get("variables", {}),
            detection=DetectionConfig.from_dict(data["detection"]),
            severity=data["severity"],
            confidence_threshold=data.get("confidence_threshold", 0.8),
            remediation=data.get("remediation", ""),
            references=data.get("references", []),
        )


@dataclass
class TestResult:
    """Result of a single test case execution."""

    id: str
    run_id: str
    test_case_id: str
    status: str  # passed, failed, error, skipped
    evidence: Optional[Evidence] = None
    severity: Optional[str] = None
    susceptibility: Optional[str] = None
    observation: Optional[str] = None
    risk_description: Optional[str] = None
    evidence_path: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "test_case_id": self.test_case_id,
            "status": self.status,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "severity": self.severity,
            "susceptibility": self.susceptibility,
            "observation": self.observation,
            "risk_description": self.risk_description,
            "evidence_path": self.evidence_path,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TestResult:
        return cls(
            id=data["id"],
            run_id=data["run_id"],
            test_case_id=data["test_case_id"],
            status=data["status"],
            evidence=Evidence.from_dict(data["evidence"])
            if data.get("evidence")
            else None,
            severity=data.get("severity"),
            susceptibility=data.get("susceptibility"),
            observation=data.get("observation"),
            risk_description=data.get("risk_description"),
            evidence_path=data.get("evidence_path"),
            started_at=datetime.fromisoformat(data["started_at"])
            if data.get("started_at")
            else None,
            completed_at=datetime.fromisoformat(data["completed_at"])
            if data.get("completed_at")
            else None,
            duration_ms=data.get("duration_ms"),
        )


@dataclass
class ScoreSummary:
    """Summary of scoring for a run."""

    total_tests: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    overall_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_tests": self.total_tests,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "skipped": self.skipped,
            "critical_findings": self.critical_findings,
            "high_findings": self.high_findings,
            "medium_findings": self.medium_findings,
            "low_findings": self.low_findings,
            "info_findings": self.info_findings,
            "overall_score": self.overall_score,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScoreSummary:
        return cls(**data)


@dataclass
class Run:
    """Single execution of a pack against a target."""

    id: str
    scope_id: str
    target_id: str
    pack_id: str
    pack_version: str
    seed: int
    created_by: str
    status: str = RunStatus.PENDING.value
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    test_count: int = 0
    passed_count: int = 0
    failed_count: int = 0
    error_count: int = 0
    score_summary: Optional[ScoreSummary] = None
    artifacts_path: Optional[str] = None

    @property
    def is_complete(self) -> bool:
        return self.status in (
            RunStatus.COMPLETED.value,
            RunStatus.FAILED.value,
            RunStatus.ABORTED.value,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scope_id": self.scope_id,
            "target_id": self.target_id,
            "pack_id": self.pack_id,
            "pack_version": self.pack_version,
            "seed": self.seed,
            "created_by": self.created_by,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat()
            if self.completed_at
            else None,
            "test_count": self.test_count,
            "passed_count": self.passed_count,
            "failed_count": self.failed_count,
            "error_count": self.error_count,
            "score_summary": self.score_summary.to_dict()
            if self.score_summary
            else None,
            "artifacts_path": self.artifacts_path,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Run:
        return cls(
            id=data["id"],
            scope_id=data["scope_id"],
            target_id=data["target_id"],
            pack_id=data["pack_id"],
            pack_version=data["pack_version"],
            seed=data["seed"],
            created_by=data["created_by"],
            status=data.get("status", RunStatus.PENDING.value),
            created_at=datetime.fromisoformat(data["created_at"]),
            started_at=datetime.fromisoformat(data["started_at"])
            if data.get("started_at")
            else None,
            completed_at=datetime.fromisoformat(data["completed_at"])
            if data.get("completed_at")
            else None,
            test_count=data.get("test_count", 0),
            passed_count=data.get("passed_count", 0),
            failed_count=data.get("failed_count", 0),
            error_count=data.get("error_count", 0),
            score_summary=ScoreSummary.from_dict(data["score_summary"])
            if data.get("score_summary")
            else None,
            artifacts_path=data.get("artifacts_path"),
        )
