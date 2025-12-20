"""Aegis MCP Server implementation.

Exposes Aegis security testing capabilities via Model Context Protocol.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from aegis import __version__
from aegis.core import (
    AegisEngine,
    SQLiteRepository,
    AuthService,
    TrustedKeyStore,
    RedactionService,
    AuditLogger,
    Principal,
    Scope,
    Run,
)
from aegis.core.exceptions import (
    AegisError,
    AuthenticationError,
    ScopeNotFoundError,
    RunNotFoundError,
    PackNotFoundError,
)

logger = logging.getLogger(__name__)


class AegisMCPServer:
    """MCP Server for Aegis security testing platform.

    Provides tools for:
    - Managing security testing scopes
    - Running security tests
    - Viewing results and reports
    - Audit log access
    """

    def __init__(
        self,
        data_path: str = "aegis_data",
        packs_path: str = "packs",
    ):
        """Initialize Aegis MCP Server.

        Args:
            data_path: Path to data directory
            packs_path: Path to test packs
        """
        self.data_path = Path(data_path)
        self.packs_path = Path(packs_path)

        # Initialize engine
        self.engine = AegisEngine(data_path=data_path)

        # Load packs
        self._load_packs()

        logger.info(f"Aegis MCP Server initialized v{__version__}")

    def _load_packs(self) -> None:
        """Load all test packs from packs directory."""
        from aegis.core.pack_loader import SecurePackLoader

        if self.packs_path.exists():
            loader = SecurePackLoader(self.packs_path)
            for pack in loader.list_packs():
                self.engine.load_pack(pack)
                logger.info(f"Loaded pack: {pack.name}")

    def get_tools(self) -> List[Dict[str, Any]]:
        """Get list of available MCP tools.

        Returns:
            List of tool definitions
        """
        return [
            {
                "name": "aegis_list_packs",
                "description": "List available security test packs",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": [],
                },
            },
            {
                "name": "aegis_pack_info",
                "description": "Get detailed information about a test pack",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "pack_name": {
                            "type": "string",
                            "description": "Name of the test pack",
                        },
                    },
                    "required": ["pack_name"],
                },
            },
            {
                "name": "aegis_create_scope",
                "description": "Create a new security testing scope",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {
                            "type": "string",
                            "description": "Scope name",
                        },
                        "targets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Target patterns (e.g., 'https://api.example.com/*')",
                        },
                        "description": {
                            "type": "string",
                            "description": "Scope description",
                        },
                    },
                    "required": ["name", "targets"],
                },
            },
            {
                "name": "aegis_list_scopes",
                "description": "List all security testing scopes",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "approved_only": {
                            "type": "boolean",
                            "description": "Only show approved scopes",
                            "default": False,
                        },
                    },
                    "required": [],
                },
            },
            {
                "name": "aegis_start_run",
                "description": "Start a security test run",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scope_id": {
                            "type": "string",
                            "description": "ID of approved scope",
                        },
                        "pack_name": {
                            "type": "string",
                            "description": "Name of test pack to run",
                        },
                    },
                    "required": ["scope_id", "pack_name"],
                },
            },
            {
                "name": "aegis_run_status",
                "description": "Get status of a test run",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {
                            "type": "string",
                            "description": "Run ID",
                        },
                    },
                    "required": ["run_id"],
                },
            },
            {
                "name": "aegis_run_results",
                "description": "Get results from a completed test run",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {
                            "type": "string",
                            "description": "Run ID",
                        },
                        "severity_filter": {
                            "type": "string",
                            "enum": ["critical", "high", "medium", "low", "info"],
                            "description": "Filter by severity",
                        },
                    },
                    "required": ["run_id"],
                },
            },
            {
                "name": "aegis_generate_report",
                "description": "Generate a security assessment report",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "run_id": {
                            "type": "string",
                            "description": "Run ID",
                        },
                        "format": {
                            "type": "string",
                            "enum": ["markdown", "json"],
                            "description": "Report format",
                            "default": "markdown",
                        },
                    },
                    "required": ["run_id"],
                },
            },
        ]

    async def call_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        principal: Principal,
    ) -> Dict[str, Any]:
        """Execute an MCP tool.

        Args:
            name: Tool name
            arguments: Tool arguments
            principal: Authenticated principal

        Returns:
            Tool result
        """
        try:
            if name == "aegis_list_packs":
                return self._list_packs()

            elif name == "aegis_pack_info":
                return self._pack_info(arguments.get("pack_name", ""))

            elif name == "aegis_create_scope":
                return self._create_scope(
                    name=arguments.get("name", ""),
                    targets=arguments.get("targets", []),
                    description=arguments.get("description"),
                    principal=principal,
                )

            elif name == "aegis_list_scopes":
                return self._list_scopes(
                    approved_only=arguments.get("approved_only", False),
                    principal=principal,
                )

            elif name == "aegis_start_run":
                return await self._start_run(
                    scope_id=arguments.get("scope_id", ""),
                    pack_name=arguments.get("pack_name", ""),
                    principal=principal,
                )

            elif name == "aegis_run_status":
                return self._run_status(
                    run_id=arguments.get("run_id", ""),
                    principal=principal,
                )

            elif name == "aegis_run_results":
                return self._run_results(
                    run_id=arguments.get("run_id", ""),
                    severity_filter=arguments.get("severity_filter"),
                    principal=principal,
                )

            elif name == "aegis_generate_report":
                return self._generate_report(
                    run_id=arguments.get("run_id", ""),
                    format=arguments.get("format", "markdown"),
                    principal=principal,
                )

            else:
                return {"error": f"Unknown tool: {name}"}

        except AegisError as e:
            return {"error": str(e)}

    def _list_packs(self) -> Dict[str, Any]:
        """List available test packs."""
        packs = self.engine.list_packs()
        return {
            "packs": [
                {
                    "name": p.name,
                    "version": p.version,
                    "description": p.description,
                    "test_count": sum(len(ts.test_cases) for ts in p.test_suites),
                }
                for p in packs
            ],
            "total": len(packs),
        }

    def _pack_info(self, pack_name: str) -> Dict[str, Any]:
        """Get pack information."""
        try:
            pack = self.engine.get_pack(pack_name)
            return {
                "name": pack.name,
                "version": pack.version,
                "description": pack.description,
                "author": pack.author,
                "test_suites": [
                    {
                        "name": ts.name,
                        "description": ts.description,
                        "test_count": len(ts.test_cases),
                    }
                    for ts in pack.test_suites
                ],
                "total_tests": sum(len(ts.test_cases) for ts in pack.test_suites),
            }
        except PackNotFoundError:
            return {"error": f"Pack not found: {pack_name}"}

    def _create_scope(
        self,
        name: str,
        targets: List[str],
        description: Optional[str],
        principal: Principal,
    ) -> Dict[str, Any]:
        """Create a new scope."""
        from aegis.core.models import Scope, TargetPattern, TimeWindow
        import uuid

        scope = Scope(
            id=str(uuid.uuid4()),
            name=name,
            owner=principal.id,
            authorized_targets=[
                TargetPattern(pattern=t, pattern_type="glob")
                for t in targets
            ],
            time_window=TimeWindow.default(),
            approvals=[],
            min_approvals=1,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow().replace(year=datetime.utcnow().year + 1),
        )

        scope_id = self.engine.create_scope(scope, principal)

        return {
            "id": scope_id,
            "name": name,
            "targets": targets,
            "status": "pending_approval",
            "message": "Scope created. Approval required before testing.",
        }

    def _list_scopes(
        self,
        approved_only: bool,
        principal: Principal,
    ) -> Dict[str, Any]:
        """List scopes."""
        scopes = self.engine.list_scopes(principal)

        if approved_only:
            scopes = [s for s in scopes if s.is_approved()]

        return {
            "scopes": [
                {
                    "id": s.id,
                    "name": s.name,
                    "approved": s.is_approved(),
                    "approvals": len(s.approvals),
                    "required_approvals": s.min_approvals,
                    "expires": s.expires_at.isoformat(),
                }
                for s in scopes
            ],
            "total": len(scopes),
        }

    async def _start_run(
        self,
        scope_id: str,
        pack_name: str,
        principal: Principal,
    ) -> Dict[str, Any]:
        """Start a test run."""
        # This would integrate with the executor to actually run tests
        # For now, create a run record

        from aegis.core.models import Run, RunStatus
        import uuid

        scope = self.engine.get_scope(scope_id, principal)
        if not scope.is_approved():
            return {"error": "Scope is not approved"}

        run = Run(
            id=str(uuid.uuid4()),
            scope_id=scope_id,
            target_id="mock-target",
            pack_id=pack_name,
            pack_version="1.0.0",
            seed=12345,
            created_by=principal.id,
            status=RunStatus.PENDING.value,
        )

        return {
            "run_id": run.id,
            "scope_id": scope_id,
            "pack": pack_name,
            "status": "started",
            "message": "Test run initiated",
        }

    def _run_status(
        self,
        run_id: str,
        principal: Principal,
    ) -> Dict[str, Any]:
        """Get run status."""
        try:
            run = self.engine.get_run(run_id, principal)
            return {
                "run_id": run.id,
                "status": run.status,
                "pack": run.pack_id,
                "tests_total": run.test_count,
                "tests_completed": run.passed_count + run.failed_count + run.error_count,
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            }
        except RunNotFoundError:
            return {"error": f"Run not found: {run_id}"}

    def _run_results(
        self,
        run_id: str,
        severity_filter: Optional[str],
        principal: Principal,
    ) -> Dict[str, Any]:
        """Get run results."""
        try:
            results = self.engine.get_test_results(run_id, principal)

            if severity_filter:
                results = [r for r in results if r.severity == severity_filter]

            return {
                "run_id": run_id,
                "results": [
                    {
                        "test_id": r.test_case_id,
                        "status": r.status,
                        "severity": r.severity,
                        "observation": r.observation,
                    }
                    for r in results
                ],
                "total": len(results),
            }
        except RunNotFoundError:
            return {"error": f"Run not found: {run_id}"}

    def _generate_report(
        self,
        run_id: str,
        format: str,
        principal: Principal,
    ) -> Dict[str, Any]:
        """Generate report."""
        try:
            report = self.engine.generate_report(run_id, principal, format=format)
            return {
                "run_id": run_id,
                "format": format,
                "content": report,
            }
        except RunNotFoundError:
            return {"error": f"Run not found: {run_id}"}


def create_mcp_server(
    data_path: str = "aegis_data",
    packs_path: str = "packs",
) -> AegisMCPServer:
    """Create and configure an Aegis MCP Server.

    Args:
        data_path: Path to data directory
        packs_path: Path to test packs

    Returns:
        Configured AegisMCPServer
    """
    return AegisMCPServer(data_path=data_path, packs_path=packs_path)
