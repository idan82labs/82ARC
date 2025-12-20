"""FastAPI application for Aegis.

Creates and configures the API application with all routes.
"""

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from aegis import __version__
from aegis.core import (
    AegisEngine,
    SQLiteRepository,
    AuthService,
    TrustedKeyStore,
    RedactionService,
    AuditLogger,
    SecurePath,
)
from aegis.core.exceptions import AegisError
from aegis.api.middleware import AuthMiddleware
from aegis.api.routes import (
    health_router,
    scope_router,
    run_router,
    pack_router,
    principal_router,
    audit_router,
)

logger = logging.getLogger(__name__)


def create_app(
    db_path: str = "aegis.db",
    packs_dir: str = "packs",
    cors_origins: Optional[list] = None,
    debug: bool = False,
) -> FastAPI:
    """Create and configure FastAPI application.

    Args:
        db_path: Path to SQLite database
        packs_dir: Path to test packs directory
        cors_origins: Allowed CORS origins (None for no CORS)
        debug: Enable debug mode

    Returns:
        Configured FastAPI application
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """Application lifespan manager."""
        logger.info(f"Starting Aegis API v{__version__}")

        # Initialize components
        repository = SQLiteRepository(db_path)
        auth_service = AuthService(repository)
        key_store = TrustedKeyStore(repository)
        redaction = RedactionService()
        audit_logger = AuditLogger(repository)

        # Create engine (without principal - auth happens per-request)
        engine = AegisEngine(
            repository=repository,
            auth_service=auth_service,
            key_store=key_store,
            redaction_service=redaction,
            audit_logger=audit_logger,
            packs_dir=Path(packs_dir),
        )

        # Store in app state
        app.state.engine = engine
        app.state.repository = repository
        app.state.auth_service = auth_service
        app.state.auth_middleware = AuthMiddleware(auth_service)

        logger.info("Aegis API initialized successfully")

        yield

        # Cleanup
        logger.info("Shutting down Aegis API")

    app = FastAPI(
        title="Aegis API",
        description="""
# Aegis - AI Security Testing Platform

REST API for the Aegis security testing platform.

## Authentication

All endpoints (except `/health`) require authentication via:
- `Authorization: Bearer <api_key>` header
- `X-API-Key: <api_key>` header

## Roles

- **admin**: Full access to all operations
- **operator**: Can create/run tests, view results
- **auditor**: Read-only access to runs and audit logs

## Workflow

1. Create a **Scope** defining test targets and constraints
2. Get **Approvals** from authorized principals (Ed25519 signatures)
3. Start a **Run** with a test pack against the approved scope
4. Monitor run progress and view **Results**
5. Export findings for remediation

## Safety Controls

- All operations are audit-logged with cryptographic integrity
- Sensitive data is automatically redacted
- Scope approval chain prevents unauthorized testing
- Time-bounded test windows with automatic expiration
        """,
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
        debug=debug,
    )

    # Add CORS if configured
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Exception handlers
    @app.exception_handler(AegisError)
    async def aegis_error_handler(request: Request, exc: AegisError):
        """Handle Aegis-specific errors."""
        return JSONResponse(
            status_code=400,
            content={"error": exc.__class__.__name__, "detail": str(exc)},
        )

    @app.exception_handler(Exception)
    async def general_error_handler(request: Request, exc: Exception):
        """Handle unexpected errors."""
        logger.exception("Unexpected error")
        if debug:
            return JSONResponse(
                status_code=500,
                content={"error": "InternalError", "detail": str(exc)},
            )
        return JSONResponse(
            status_code=500,
            content={"error": "InternalError", "detail": "An unexpected error occurred"},
        )

    # Include routers
    app.include_router(health_router)
    app.include_router(scope_router, prefix="/api/v1")
    app.include_router(run_router, prefix="/api/v1")
    app.include_router(pack_router, prefix="/api/v1")
    app.include_router(principal_router, prefix="/api/v1")
    app.include_router(audit_router, prefix="/api/v1")

    return app


# Default app instance for uvicorn
app = create_app()


def run_server(
    host: str = "0.0.0.0",
    port: int = 8000,
    db_path: str = "aegis.db",
    packs_dir: str = "packs",
    reload: bool = False,
):
    """Run the API server.

    Args:
        host: Host to bind to
        port: Port to listen on
        db_path: Database path
        packs_dir: Packs directory
        reload: Enable auto-reload (dev only)
    """
    import uvicorn

    # Create app with custom config
    application = create_app(db_path=db_path, packs_dir=packs_dir)

    uvicorn.run(
        application,
        host=host,
        port=port,
        reload=reload,
    )


if __name__ == "__main__":
    run_server()
