"""Pydantic schemas for Aegis API.

Defines request/response models with validation.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ============================================================================
# Enums
# ============================================================================


class RunStatusEnum(str, Enum):
    """Test run status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class SeverityEnum(str, Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TestStatusEnum(str, Enum):
    """Individual test status."""
    PENDING = "pending"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    ERROR = "error"


# ============================================================================
# Request Schemas
# ============================================================================


class ScopeCreateRequest(BaseModel):
    """Request to create a new scope."""
    name: str = Field(..., min_length=1, max_length=256, description="Scope name")
    description: Optional[str] = Field(None, max_length=2048, description="Scope description")
    target_patterns: List[str] = Field(..., min_length=1, description="Target patterns")
    required_approvals: int = Field(1, ge=1, le=10, description="Required approvals")
    time_window_start: Optional[datetime] = Field(None, description="Testing window start")
    time_window_end: Optional[datetime] = Field(None, description="Testing window end")
    restrictions: Optional[Dict[str, Any]] = Field(None, description="Additional restrictions")

    @field_validator("target_patterns")
    @classmethod
    def validate_targets(cls, v: List[str]) -> List[str]:
        """Ensure non-empty patterns."""
        if not v:
            raise ValueError("At least one target pattern required")
        for pattern in v:
            if not pattern or not pattern.strip():
                raise ValueError("Empty target patterns not allowed")
        return [p.strip() for p in v]


class ScopeApproveRequest(BaseModel):
    """Request to approve a scope."""
    signature: str = Field(..., description="Ed25519 signature (base64)")
    comment: Optional[str] = Field(None, max_length=1024, description="Approval comment")


class RunCreateRequest(BaseModel):
    """Request to start a new test run."""
    scope_id: str = Field(..., description="Scope ID")
    pack_name: str = Field(..., min_length=1, description="Test pack name")
    config: Optional[Dict[str, Any]] = Field(None, description="Run configuration")


class RunAbortRequest(BaseModel):
    """Request to abort a run."""
    reason: str = Field("Manual abort", max_length=1024, description="Abort reason")


class PrincipalCreateRequest(BaseModel):
    """Request to create a new principal."""
    name: str = Field(..., min_length=1, max_length=256, description="Principal name")
    roles: List[str] = Field(["operator"], description="Assigned roles")

    @field_validator("roles")
    @classmethod
    def validate_roles(cls, v: List[str]) -> List[str]:
        """Validate role names."""
        valid_roles = {"admin", "operator", "auditor"}
        for role in v:
            if role not in valid_roles:
                raise ValueError(f"Invalid role: {role}. Must be one of: {valid_roles}")
        return v


class PublicKeyRegisterRequest(BaseModel):
    """Request to register a public key."""
    public_key_pem: str = Field(..., description="Ed25519 public key in PEM format")


# ============================================================================
# Response Schemas
# ============================================================================


class TargetPatternResponse(BaseModel):
    """Target pattern in response."""
    pattern: str
    pattern_type: str
    description: Optional[str] = None


class ApprovalResponse(BaseModel):
    """Approval in response."""
    approver_id: str
    approved_at: datetime
    comment: Optional[str] = None


class ScopeResponse(BaseModel):
    """Scope response model."""
    id: str
    name: str
    description: Optional[str] = None
    targets: List[TargetPatternResponse]
    required_approvals: int
    approvals: List[ApprovalResponse]
    is_approved: bool
    time_window_start: Optional[datetime] = None
    time_window_end: Optional[datetime] = None
    created_at: datetime
    created_by: str


class ScopeListResponse(BaseModel):
    """List of scopes response."""
    scopes: List[ScopeResponse]
    total: int


class TestResultResponse(BaseModel):
    """Test result in response."""
    test_id: str
    test_name: str
    status: TestStatusEnum
    severity: Optional[SeverityEnum] = None
    message: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScoreSummaryResponse(BaseModel):
    """Score summary in response."""
    total_tests: int
    passed: int
    failed: int
    skipped: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    score: float


class RunResponse(BaseModel):
    """Run response model."""
    id: str
    scope_id: str
    pack_name: str
    status: RunStatusEnum
    tests_total: int
    tests_completed: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_by: str
    score_summary: Optional[ScoreSummaryResponse] = None


class RunListResponse(BaseModel):
    """List of runs response."""
    runs: List[RunResponse]
    total: int


class RunResultsResponse(BaseModel):
    """Run results response."""
    run_id: str
    status: RunStatusEnum
    results: List[TestResultResponse]
    score_summary: Optional[ScoreSummaryResponse] = None


class PackInfoResponse(BaseModel):
    """Pack information response."""
    name: str
    version: str
    description: Optional[str] = None
    author: Optional[str] = None
    test_suites: List[str]
    total_tests: int


class PackListResponse(BaseModel):
    """List of packs response."""
    packs: List[PackInfoResponse]
    total: int


class PrincipalResponse(BaseModel):
    """Principal response model."""
    id: str
    name: str
    roles: List[str]
    is_revoked: bool
    has_public_key: bool
    public_key_fingerprint: Optional[str] = None
    created_at: datetime
    last_active: Optional[datetime] = None


class PrincipalCreateResponse(BaseModel):
    """Response after creating principal."""
    principal: PrincipalResponse
    api_key: str = Field(..., description="API key (only shown once)")


class PrincipalListResponse(BaseModel):
    """List of principals response."""
    principals: List[PrincipalResponse]
    total: int


class ErrorResponse(BaseModel):
    """Error response model."""
    error: str
    detail: Optional[str] = None
    code: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str
    database: str = "connected"


class AuditEntryResponse(BaseModel):
    """Audit log entry response."""
    id: str
    timestamp: datetime
    principal_id: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    hash: str


class AuditListResponse(BaseModel):
    """Audit log list response."""
    entries: List[AuditEntryResponse]
    total: int
