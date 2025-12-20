"""API routes for Aegis.

Implements RESTful endpoints with OpenAPI documentation.
"""

import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from aegis.core import (
    AegisEngine,
    Principal,
    Scope,
    Run,
    TestResult,
    RunStatus,
    Severity,
)
from aegis.core.exceptions import (
    AegisError,
    ScopeNotFoundError,
    ScopeNotApprovedError,
    RunNotFoundError,
    PackNotFoundError,
)
from aegis.api.schemas import (
    # Requests
    ScopeCreateRequest,
    ScopeApproveRequest,
    RunCreateRequest,
    RunAbortRequest,
    PrincipalCreateRequest,
    PublicKeyRegisterRequest,
    # Responses
    ScopeResponse,
    ScopeListResponse,
    TargetPatternResponse,
    ApprovalResponse,
    RunResponse,
    RunListResponse,
    RunResultsResponse,
    TestResultResponse,
    ScoreSummaryResponse,
    PackInfoResponse,
    PackListResponse,
    PrincipalResponse,
    PrincipalCreateResponse,
    PrincipalListResponse,
    AuditEntryResponse,
    AuditListResponse,
    HealthResponse,
    ErrorResponse,
    RunStatusEnum,
    SeverityEnum,
    TestStatusEnum,
)
from aegis.api.middleware import AuthMiddleware

logger = logging.getLogger(__name__)

# Create routers
health_router = APIRouter(tags=["Health"])
scope_router = APIRouter(prefix="/scopes", tags=["Scopes"])
run_router = APIRouter(prefix="/runs", tags=["Runs"])
pack_router = APIRouter(prefix="/packs", tags=["Packs"])
principal_router = APIRouter(prefix="/principals", tags=["Principals"])
audit_router = APIRouter(prefix="/audit", tags=["Audit"])


def get_engine(request: Request) -> AegisEngine:
    """Get engine from request state."""
    return request.app.state.engine


def get_auth(request: Request) -> AuthMiddleware:
    """Get auth middleware from request state."""
    return request.app.state.auth_middleware


# ============================================================================
# Health Endpoints
# ============================================================================


@health_router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check API health status",
)
async def health_check(request: Request) -> HealthResponse:
    """Health check endpoint."""
    from aegis import __version__
    return HealthResponse(
        status="healthy",
        version=__version__,
        database="connected",
    )


# ============================================================================
# Scope Endpoints
# ============================================================================


@scope_router.post(
    "",
    response_model=ScopeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create scope",
    description="Create a new security testing scope",
    responses={401: {"model": ErrorResponse}, 403: {"model": ErrorResponse}},
)
async def create_scope(
    request: Request,
    body: ScopeCreateRequest,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_permission("create", "scope")(r)),
) -> ScopeResponse:
    """Create a new scope."""
    engine = get_engine(request)

    try:
        scope = engine.create_scope(
            name=body.name,
            description=body.description,
            target_patterns=body.target_patterns,
            required_approvals=body.required_approvals,
            time_window_start=body.time_window_start,
            time_window_end=body.time_window_end,
        )
        return _scope_to_response(scope)
    except AegisError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@scope_router.get(
    "",
    response_model=ScopeListResponse,
    summary="List scopes",
    description="List all scopes with optional filtering",
)
async def list_scopes(
    request: Request,
    approved_only: bool = Query(False, description="Only show approved scopes"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_permission("read", "scope")(r)),
) -> ScopeListResponse:
    """List scopes."""
    engine = get_engine(request)
    scopes = engine.list_scopes()

    if approved_only:
        scopes = [s for s in scopes if s.is_approved()]

    total = len(scopes)
    scopes = scopes[offset : offset + limit]

    return ScopeListResponse(
        scopes=[_scope_to_response(s) for s in scopes],
        total=total,
    )


@scope_router.get(
    "/{scope_id}",
    response_model=ScopeResponse,
    summary="Get scope",
    description="Get scope details by ID",
    responses={404: {"model": ErrorResponse}},
)
async def get_scope(
    request: Request,
    scope_id: str,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_permission("read", "scope")(r)),
) -> ScopeResponse:
    """Get scope by ID."""
    engine = get_engine(request)

    try:
        scope = engine.get_scope(scope_id)
        return _scope_to_response(scope)
    except ScopeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scope not found: {scope_id}")


@scope_router.post(
    "/{scope_id}/approve",
    response_model=ScopeResponse,
    summary="Approve scope",
    description="Add approval signature to scope",
)
async def approve_scope(
    request: Request,
    scope_id: str,
    body: ScopeApproveRequest,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_permission("approve", "scope")(r)),
) -> ScopeResponse:
    """Approve a scope."""
    engine = get_engine(request)

    try:
        scope = engine.approve_scope(
            scope_id=scope_id,
            signature=body.signature,
            comment=body.comment,
        )
        return _scope_to_response(scope)
    except ScopeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scope not found: {scope_id}")
    except AegisError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ============================================================================
# Run Endpoints
# ============================================================================


@run_router.post(
    "",
    response_model=RunResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start run",
    description="Start a new test run against an approved scope",
    responses={400: {"model": ErrorResponse}, 404: {"model": ErrorResponse}},
)
async def create_run(
    request: Request,
    body: RunCreateRequest,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_permission("create", "run")(r)),
) -> RunResponse:
    """Start a new run."""
    engine = get_engine(request)

    try:
        run = engine.start_run(
            scope_id=body.scope_id,
            pack_name=body.pack_name,
            config=body.config,
        )
        return _run_to_response(run)
    except ScopeNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scope not found: {body.scope_id}")
    except ScopeNotApprovedError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scope not approved")
    except PackNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Pack not found: {body.pack_name}")
    except AegisError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@run_router.get(
    "",
    response_model=RunListResponse,
    summary="List runs",
    description="List test runs with optional filtering",
)
async def list_runs(
    request: Request,
    scope_id: Optional[str] = Query(None, description="Filter by scope ID"),
    status_filter: Optional[RunStatusEnum] = Query(None, alias="status", description="Filter by status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_permission("read", "run")(r)),
) -> RunListResponse:
    """List runs."""
    engine = get_engine(request)
    runs = engine.list_runs(scope_id=scope_id, limit=limit + offset)

    if status_filter:
        runs = [r for r in runs if r.status.value == status_filter.value]

    total = len(runs)
    runs = runs[offset : offset + limit]

    return RunListResponse(
        runs=[_run_to_response(r) for r in runs],
        total=total,
    )


@run_router.get(
    "/{run_id}",
    response_model=RunResponse,
    summary="Get run",
    description="Get run details by ID",
    responses={404: {"model": ErrorResponse}},
)
async def get_run(
    request: Request,
    run_id: str,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_permission("read", "run")(r)),
) -> RunResponse:
    """Get run by ID."""
    engine = get_engine(request)

    try:
        run = engine.get_run(run_id)
        return _run_to_response(run)
    except RunNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Run not found: {run_id}")


@run_router.get(
    "/{run_id}/results",
    response_model=RunResultsResponse,
    summary="Get run results",
    description="Get detailed test results for a run",
    responses={404: {"model": ErrorResponse}},
)
async def get_run_results(
    request: Request,
    run_id: str,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_permission("read", "run")(r)),
) -> RunResultsResponse:
    """Get run results."""
    engine = get_engine(request)

    try:
        run = engine.get_run(run_id)
        results = engine.get_run_results(run_id)

        return RunResultsResponse(
            run_id=run.id,
            status=RunStatusEnum(run.status.value),
            results=[_result_to_response(r) for r in results],
            score_summary=_score_to_response(run.score_summary) if run.score_summary else None,
        )
    except RunNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Run not found: {run_id}")


@run_router.post(
    "/{run_id}/abort",
    response_model=RunResponse,
    summary="Abort run",
    description="Abort a running test",
    responses={404: {"model": ErrorResponse}},
)
async def abort_run(
    request: Request,
    run_id: str,
    body: RunAbortRequest,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_permission("abort", "run")(r)),
) -> RunResponse:
    """Abort a run."""
    engine = get_engine(request)

    try:
        run = engine.abort_run(run_id, reason=body.reason)
        return _run_to_response(run)
    except RunNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Run not found: {run_id}")
    except AegisError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ============================================================================
# Pack Endpoints
# ============================================================================


@pack_router.get(
    "",
    response_model=PackListResponse,
    summary="List packs",
    description="List available test packs",
)
async def list_packs(
    request: Request,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.get_current_principal(r)),
) -> PackListResponse:
    """List available packs."""
    engine = get_engine(request)
    packs = engine.list_packs()

    return PackListResponse(
        packs=[
            PackInfoResponse(
                name=p.name,
                version=p.version,
                description=p.description,
                author=p.author,
                test_suites=[ts.name for ts in p.test_suites],
                total_tests=sum(len(ts.test_cases) for ts in p.test_suites),
            )
            for p in packs
        ],
        total=len(packs),
    )


@pack_router.get(
    "/{pack_name}",
    response_model=PackInfoResponse,
    summary="Get pack",
    description="Get pack details by name",
    responses={404: {"model": ErrorResponse}},
)
async def get_pack(
    request: Request,
    pack_name: str,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.get_current_principal(r)),
) -> PackInfoResponse:
    """Get pack by name."""
    engine = get_engine(request)

    try:
        pack = engine.get_pack(pack_name)
        return PackInfoResponse(
            name=pack.name,
            version=pack.version,
            description=pack.description,
            author=pack.author,
            test_suites=[ts.name for ts in pack.test_suites],
            total_tests=sum(len(ts.test_cases) for ts in pack.test_suites),
        )
    except PackNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Pack not found: {pack_name}")


# ============================================================================
# Principal Endpoints
# ============================================================================


@principal_router.post(
    "",
    response_model=PrincipalCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create principal",
    description="Create a new principal (requires admin)",
    responses={403: {"model": ErrorResponse}},
)
async def create_principal(
    request: Request,
    body: PrincipalCreateRequest,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_admin()(r)),
) -> PrincipalCreateResponse:
    """Create a new principal."""
    engine = get_engine(request)

    try:
        new_principal, api_key = engine.create_principal(
            name=body.name,
            roles=body.roles,
        )
        return PrincipalCreateResponse(
            principal=_principal_to_response(new_principal),
            api_key=api_key,
        )
    except AegisError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@principal_router.get(
    "",
    response_model=PrincipalListResponse,
    summary="List principals",
    description="List all principals (requires admin)",
)
async def list_principals(
    request: Request,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_admin()(r)),
) -> PrincipalListResponse:
    """List all principals."""
    engine = get_engine(request)
    principals = engine.list_principals()

    return PrincipalListResponse(
        principals=[_principal_to_response(p) for p in principals],
        total=len(principals),
    )


@principal_router.get(
    "/me",
    response_model=PrincipalResponse,
    summary="Get current principal",
    description="Get details of the currently authenticated principal",
)
async def get_current_principal(
    request: Request,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.get_current_principal(r)),
) -> PrincipalResponse:
    """Get current principal."""
    return _principal_to_response(principal)


@principal_router.post(
    "/{principal_id}/public-key",
    response_model=PrincipalResponse,
    summary="Register public key",
    description="Register Ed25519 public key for a principal (requires admin)",
)
async def register_public_key(
    request: Request,
    principal_id: str,
    body: PublicKeyRegisterRequest,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_admin()(r)),
) -> PrincipalResponse:
    """Register public key for principal."""
    engine = get_engine(request)

    try:
        updated = engine.register_public_key(
            principal_id=principal_id,
            public_key_pem=body.public_key_pem,
        )
        return _principal_to_response(updated)
    except AegisError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@principal_router.delete(
    "/{principal_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke principal",
    description="Revoke a principal's access (requires admin)",
)
async def revoke_principal(
    request: Request,
    principal_id: str,
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_admin()(r)),
) -> None:
    """Revoke a principal."""
    engine = get_engine(request)

    try:
        engine.revoke_principal(principal_id)
    except AegisError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ============================================================================
# Audit Endpoints
# ============================================================================


@audit_router.get(
    "",
    response_model=AuditListResponse,
    summary="List audit entries",
    description="List audit log entries (requires auditor role)",
)
async def list_audit_entries(
    request: Request,
    principal_id: Optional[str] = Query(None, description="Filter by principal"),
    action: Optional[str] = Query(None, description="Filter by action"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type"),
    since: Optional[datetime] = Query(None, description="Filter since timestamp"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    principal: Principal = Depends(lambda r: r.app.state.auth_middleware.require_permission("read", "audit")(r)),
) -> AuditListResponse:
    """List audit entries."""
    engine = get_engine(request)

    entries = engine.list_audit_entries(
        principal_id=principal_id,
        action=action,
        resource_type=resource_type,
        since=since,
        limit=limit + offset,
    )

    total = len(entries)
    entries = entries[offset : offset + limit]

    return AuditListResponse(
        entries=[
            AuditEntryResponse(
                id=e.id,
                timestamp=e.timestamp,
                principal_id=e.principal_id,
                action=e.action,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                details=e.details,
                hash=e.hash,
            )
            for e in entries
        ],
        total=total,
    )


# ============================================================================
# Helper Functions
# ============================================================================


def _scope_to_response(scope: Scope) -> ScopeResponse:
    """Convert Scope model to response."""
    return ScopeResponse(
        id=scope.id,
        name=scope.name,
        description=scope.description,
        targets=[
            TargetPatternResponse(
                pattern=t.pattern,
                pattern_type=t.pattern_type,
                description=t.description,
            )
            for t in scope.targets
        ],
        required_approvals=scope.required_approvals,
        approvals=[
            ApprovalResponse(
                approver_id=a.approver_id,
                approved_at=a.approved_at,
                comment=a.comment,
            )
            for a in scope.approvals
        ],
        is_approved=scope.is_approved(),
        time_window_start=scope.time_window.start if scope.time_window else None,
        time_window_end=scope.time_window.end if scope.time_window else None,
        created_at=scope.created_at,
        created_by=scope.created_by,
    )


def _run_to_response(run: Run) -> RunResponse:
    """Convert Run model to response."""
    return RunResponse(
        id=run.id,
        scope_id=run.scope_id,
        pack_name=run.pack_name,
        status=RunStatusEnum(run.status.value),
        tests_total=run.tests_total,
        tests_completed=run.tests_completed,
        started_at=run.started_at,
        completed_at=run.completed_at,
        created_by=run.created_by,
        score_summary=_score_to_response(run.score_summary) if run.score_summary else None,
    )


def _result_to_response(result: TestResult) -> TestResultResponse:
    """Convert TestResult model to response."""
    return TestResultResponse(
        test_id=result.test_id,
        test_name=result.test_name,
        status=TestStatusEnum(result.status.value),
        severity=SeverityEnum(result.severity.value) if result.severity else None,
        message=result.message,
        evidence=result.evidence.to_dict() if result.evidence else None,
        started_at=result.started_at,
        completed_at=result.completed_at,
    )


def _score_to_response(score) -> ScoreSummaryResponse:
    """Convert ScoreSummary to response."""
    return ScoreSummaryResponse(
        total_tests=score.total_tests,
        passed=score.passed,
        failed=score.failed,
        skipped=score.skipped,
        critical_findings=score.critical_findings,
        high_findings=score.high_findings,
        medium_findings=score.medium_findings,
        low_findings=score.low_findings,
        score=score.score,
    )


def _principal_to_response(principal: Principal) -> PrincipalResponse:
    """Convert Principal model to response."""
    return PrincipalResponse(
        id=principal.id,
        name=principal.name,
        roles=principal.roles,
        is_revoked=principal.is_revoked,
        has_public_key=principal.public_key is not None,
        public_key_fingerprint=principal.public_key_fingerprint,
        created_at=principal.created_at,
        last_active=principal.last_active,
    )
