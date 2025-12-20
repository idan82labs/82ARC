"""Main Aegis Engine - orchestrates all testing operations.

This is the single source of truth for all business logic.
CLI, REST, and MCP interfaces all call this engine.
"""

import logging
import random
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis.core.auth import AuthService, TrustedKeyStore
from aegis.core.audit import AuditLogger
from aegis.core.exceptions import (
    AuthorizationError,
    InsufficientApprovalsError,
    OutsideTimeWindowError,
    RateLimitExceededError,
    RunNotFoundError,
    ScopeExpiredError,
    ScopeNotFoundError,
    TargetNotAuthorizedError,
    TestCaseRestrictedError,
    UnauthorizedOperatorError,
)
from aegis.core.models import (
    Evidence,
    Principal,
    Run,
    RunStatus,
    Scope,
    ScoreSummary,
    Target,
    TestCase,
    TestResult,
    TestStatus,
)
from aegis.core.redaction import RedactionService
from aegis.core.repository import Repository, SQLiteRepository
from aegis.core.storage import DataEncryption, SecurePath

if TYPE_CHECKING:
    from aegis.core.pack_loader import Pack

logger = logging.getLogger(__name__)


class AegisEngine:
    """Main engine for Aegis AI Security Testing Platform.

    All interfaces (CLI, REST, MCP) use this engine.
    """

    def __init__(
        self,
        repository: Optional[Repository] = None,
        data_path: str = "aegis_data",
        encryption: Optional[DataEncryption] = None,
        audit_signing_key: Optional[Ed25519PrivateKey] = None,
    ):
        """Initialize Aegis Engine.

        Args:
            repository: Repository for persistence (defaults to SQLite)
            data_path: Base path for data storage
            encryption: Optional encryption for sensitive data
            audit_signing_key: Ed25519 key for signing audit entries
        """
        self.data_path = Path(data_path)
        self.data_path.mkdir(parents=True, exist_ok=True)

        # Initialize encryption
        self.encryption = encryption
        if not self.encryption:
            key_path = self.data_path / "keys" / "data.key"
            if key_path.exists() or not key_path.parent.exists():
                key_path.parent.mkdir(parents=True, exist_ok=True)
            # Create encryption but warn if not explicitly configured
            self.encryption = DataEncryption(key_path)

        # Initialize repository
        self.repository = repository or SQLiteRepository(
            db_path=str(self.data_path / "aegis.db"),
            encryption=self.encryption,
        )

        # Initialize services
        self.auth = AuthService(self.repository)
        self.keystore = TrustedKeyStore(self.repository)
        self.redaction = RedactionService()

        # Initialize audit logger
        if audit_signing_key:
            self._audit_key = audit_signing_key
        else:
            # Generate a new signing key for this session
            self._audit_key = Ed25519PrivateKey.generate()
            logger.warning(
                "Generated ephemeral audit signing key. "
                "For production, provide a persistent key."
            )

        self.audit = AuditLogger(
            repository=self.repository,
            signing_key=self._audit_key,
            redaction=self.redaction,
        )

        # Artifact storage
        self.artifacts_path = SecurePath(self.data_path / "artifacts")

        # Pack registry (loaded packs)
        self._packs: Dict[str, "Pack"] = {}

        logger.info(f"Aegis Engine initialized with data at {self.data_path}")

    # ==================== Authentication ====================

    def authenticate(self, api_key: str) -> Principal:
        """Authenticate a principal via API key.

        Args:
            api_key: API key to authenticate

        Returns:
            Authenticated Principal
        """
        return self.auth.authenticate_api_key(api_key)

    # ==================== Scope Management ====================

    def create_scope(self, scope: Scope, principal: Principal) -> str:
        """Create a new testing scope.

        Args:
            scope: Scope to create
            principal: Principal creating the scope

        Returns:
            Scope ID
        """
        self.auth.authorize(principal, "create", "scope")

        # Validate scope
        if scope.min_approvals < 1:
            raise ValueError("Scope must require at least 1 approval")

        # Save scope
        scope_id = self.repository.save_scope(scope)

        # Audit
        self.audit.log(
            principal_id=principal.id,
            action="scope.create",
            target=scope_id,
            scope_id=scope_id,
            details={"name": scope.name, "owner": scope.owner},
        )

        logger.info(f"Created scope {scope_id} by {principal.id}")
        return scope_id

    def get_scope(self, scope_id: str, principal: Principal) -> Scope:
        """Get a scope by ID.

        Args:
            scope_id: Scope ID
            principal: Principal requesting the scope

        Returns:
            Scope object
        """
        self.auth.authorize(principal, "read", "scope")

        scope = self.repository.get_scope(scope_id)
        if not scope:
            raise ScopeNotFoundError(f"Scope {scope_id} not found")
        return scope

    def verify_scope(
        self,
        scope: Scope,
        target: Target,
        test_case: Optional[TestCase],
        principal: Principal,
    ) -> bool:
        """Verify that a scope allows the requested operation.

        Args:
            scope: Scope to verify
            target: Target to test
            test_case: Optional test case to run
            principal: Principal performing the operation

        Returns:
            True if verified

        Raises:
            Various ScopeError subclasses if verification fails
        """
        # 0. Principal must have operator role
        if not principal.is_operator():
            raise UnauthorizedOperatorError(
                f"Principal {principal.id} is not an operator"
            )

        # 1. Scope not expired
        if datetime.utcnow() > scope.expires_at:
            raise ScopeExpiredError(f"Scope {scope.id} expired at {scope.expires_at}")

        # 2. Approval chain verified
        scope_hash = scope.compute_hash()
        verified_approvals = 0
        skipped_reasons = []

        for approval in scope.approvals:
            public_key = self.keystore.get_trusted_key(approval.approver_id)
            if not public_key:
                skipped_reasons.append(
                    f"Approval from {approval.approver_id}: no registered public key"
                )
                logger.warning(
                    f"Skipped approval from {approval.approver_id} - no registered key"
                )
                continue

            if not self.keystore.verify_fingerprint(
                approval.approver_id, approval.public_key_fingerprint
            ):
                skipped_reasons.append(
                    f"Approval from {approval.approver_id}: fingerprint mismatch"
                )
                logger.warning(
                    f"Skipped approval from {approval.approver_id} - fingerprint mismatch"
                )
                continue

            if approval.verify(scope_hash, public_key):
                verified_approvals += 1
            else:
                skipped_reasons.append(
                    f"Approval from {approval.approver_id}: invalid signature"
                )
                logger.warning(
                    f"Skipped approval from {approval.approver_id} - invalid signature"
                )

        if verified_approvals < scope.min_approvals:
            raise InsufficientApprovalsError(
                f"Scope requires {scope.min_approvals} approvals, "
                f"only {verified_approvals} verified. Reasons: {skipped_reasons}"
            )

        # 3. Target in authorized list
        if not scope.allows_target(target.url):
            raise TargetNotAuthorizedError(
                f"Target {target.url} not matched by any authorized pattern"
            )

        # 4. Within time window
        if not scope.time_window.is_active():
            raise OutsideTimeWindowError(
                f"Current time outside window "
                f"{scope.time_window.start} - {scope.time_window.end}"
            )

        # 5. Request limits not exceeded
        if scope.requests_remaining <= 0:
            raise RateLimitExceededError(
                f"Scope {scope.id} has exhausted request limit"
            )

        # 6. Test case not in restrictions (if provided)
        if test_case and scope.restrictions and scope.restrictions.blocks(test_case):
            raise TestCaseRestrictedError(
                f"Test case {test_case.id} blocked by scope restrictions"
            )

        return True

    # ==================== Target Management ====================

    def create_target(self, target: Target, principal: Principal) -> str:
        """Create a new target.

        Args:
            target: Target to create
            principal: Principal creating the target

        Returns:
            Target ID
        """
        self.auth.authorize(principal, "create", "target")

        target.created_by = principal.id
        target_id = self.repository.save_target(target)

        self.audit.log(
            principal_id=principal.id,
            action="target.create",
            target=target_id,
            details={"name": target.name, "type": target.type},
        )

        logger.info(f"Created target {target_id} by {principal.id}")
        return target_id

    def get_target(self, target_id: str, principal: Principal) -> Target:
        """Get a target by ID.

        Args:
            target_id: Target ID
            principal: Principal requesting the target

        Returns:
            Target object
        """
        self.auth.authorize(principal, "read", "target")

        target = self.repository.get_target(target_id)
        if not target:
            raise ValueError(f"Target {target_id} not found")
        return target

    # ==================== Run Management ====================

    def create_run(
        self,
        scope_id: str,
        target_id: str,
        pack_id: str,
        principal: Principal,
        seed: Optional[int] = None,
    ) -> Run:
        """Create a new test run.

        Args:
            scope_id: Scope ID
            target_id: Target ID
            pack_id: Pack ID
            principal: Principal creating the run
            seed: Optional seed for determinism (random if not provided)

        Returns:
            Created Run object
        """
        self.auth.authorize(principal, "create", "run")

        # Get scope and target
        scope = self.get_scope(scope_id, principal)
        target = self.get_target(target_id, principal)

        # Verify scope allows this target
        self.verify_scope(scope, target, None, principal)

        # Generate seed if not provided
        if seed is None:
            seed = random.randint(0, 2**32 - 1)

        # Get pack version
        pack = self._packs.get(pack_id)
        pack_version = pack.version if pack else "unknown"

        # Create run
        run = Run(
            id=str(uuid.uuid4()),
            scope_id=scope_id,
            target_id=target_id,
            pack_id=pack_id,
            pack_version=pack_version,
            seed=seed,
            created_by=principal.id,
            status=RunStatus.PENDING.value,
            artifacts_path=None,
        )

        # Save run
        self.repository.save_run(run)

        # Audit
        self.audit.log(
            principal_id=principal.id,
            action="run.create",
            target=run.id,
            run_id=run.id,
            scope_id=scope_id,
            details={"pack_id": pack_id, "target_id": target_id, "seed": seed},
        )

        logger.info(f"Created run {run.id} by {principal.id}")
        return run

    def get_run(self, run_id: str, principal: Principal) -> Run:
        """Get a run by ID.

        Args:
            run_id: Run ID
            principal: Principal requesting the run

        Returns:
            Run object
        """
        self.auth.authorize(principal, "read", "run")

        run = self.repository.get_run(run_id)
        if not run:
            raise RunNotFoundError(f"Run {run_id} not found")
        return run

    def list_runs(
        self,
        principal: Principal,
        scope_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 100,
    ) -> List[Run]:
        """List runs.

        Args:
            principal: Principal requesting the list
            scope_id: Optional scope filter
            status: Optional status filter
            limit: Maximum runs to return

        Returns:
            List of Run objects
        """
        self.auth.authorize(principal, "read", "run")
        return self.repository.list_runs(scope_id=scope_id, status=status, limit=limit)

    def start_run(self, run_id: str, principal: Principal) -> Run:
        """Start executing a run.

        Args:
            run_id: Run ID
            principal: Principal starting the run

        Returns:
            Updated Run object
        """
        self.auth.authorize(principal, "create", "run")

        run = self.get_run(run_id, principal)
        if run.status != RunStatus.PENDING.value:
            raise ValueError(f"Run {run_id} is not in pending state")

        # Update status
        now = datetime.utcnow()
        self.repository.update_run_status(
            run_id, RunStatus.RUNNING.value, started_at=now
        )

        # Audit
        self.audit.log(
            principal_id=principal.id,
            action="run.start",
            target=run_id,
            run_id=run_id,
            scope_id=run.scope_id,
        )

        logger.info(f"Started run {run_id} by {principal.id}")

        # Refresh and return
        return self.get_run(run_id, principal)

    def complete_run(
        self,
        run_id: str,
        principal: Principal,
        status: str = RunStatus.COMPLETED.value,
    ) -> Run:
        """Mark a run as complete.

        Args:
            run_id: Run ID
            principal: Principal completing the run
            status: Final status (completed, failed, aborted)

        Returns:
            Updated Run object
        """
        run = self.get_run(run_id, principal)

        now = datetime.utcnow()
        self.repository.update_run_status(run_id, status, completed_at=now)

        # Calculate summary
        results = self.repository.get_test_results(run_id)
        summary = self._calculate_summary(results)
        self.repository.update_run_summary(run_id, summary)

        # Audit
        self.audit.log(
            principal_id=principal.id,
            action=f"run.{status}",
            target=run_id,
            run_id=run_id,
            scope_id=run.scope_id,
            details={
                "total_tests": summary.total_tests,
                "passed": summary.passed,
                "failed": summary.failed,
            },
        )

        logger.info(f"Completed run {run_id} with status {status}")
        return self.get_run(run_id, principal)

    def abort_run(self, run_id: str, principal: Principal) -> Run:
        """Abort a running test.

        Args:
            run_id: Run ID
            principal: Principal aborting the run

        Returns:
            Updated Run object
        """
        self.auth.authorize(principal, "abort", "run")
        return self.complete_run(run_id, principal, RunStatus.ABORTED.value)

    # ==================== Test Result Management ====================

    def record_test_result(
        self,
        run_id: str,
        test_case: TestCase,
        status: str,
        evidence: Optional[Evidence] = None,
        observation: Optional[str] = None,
        principal: Optional[Principal] = None,
    ) -> TestResult:
        """Record a test result.

        Args:
            run_id: Run ID
            test_case: Test case that was executed
            status: Test status
            evidence: Optional evidence (will be redacted)
            observation: What was observed
            principal: Principal recording the result

        Returns:
            Created TestResult
        """
        result_id = str(uuid.uuid4())

        # Store evidence if provided
        evidence_path = None
        if evidence:
            # Redact evidence before storage
            redacted_request = self.redaction.redact(evidence.request)
            redacted_response = self.redaction.redact(evidence.response)
            redacted_evidence = Evidence(
                request=redacted_request,
                response=redacted_response,
                timestamp=evidence.timestamp,
                headers=self.redaction.redact_dict(evidence.headers or {}),
                metadata=evidence.metadata,
            )

            # Store to file
            import json

            evidence_dir = self.artifacts_path.mkdir(run_id)
            evidence_file = evidence_dir / f"{result_id}.json"
            with open(evidence_file, "w") as f:
                json.dump(redacted_evidence.to_dict(), f, indent=2)
            evidence_path = f"{run_id}/{result_id}.json"

        # Determine susceptibility
        susceptibility = "none"
        if status == TestStatus.FAILED.value:
            severity_map = {
                "critical": "high",
                "high": "high",
                "medium": "moderate",
                "low": "low",
                "info": "low",
            }
            susceptibility = severity_map.get(test_case.severity, "moderate")

        result = TestResult(
            id=result_id,
            run_id=run_id,
            test_case_id=test_case.id,
            status=status,
            severity=test_case.severity if status == TestStatus.FAILED.value else None,
            susceptibility=susceptibility,
            observation=observation,
            evidence=evidence,
            evidence_path=evidence_path,
            started_at=datetime.utcnow(),
            completed_at=datetime.utcnow(),
        )

        self.repository.save_test_result(result)

        # Update run counts
        run = self.repository.get_run(run_id)
        if run:
            passed = run.passed_count + (1 if status == TestStatus.PASSED.value else 0)
            failed = run.failed_count + (1 if status == TestStatus.FAILED.value else 0)
            errors = run.error_count + (1 if status == TestStatus.ERROR.value else 0)
            total = run.test_count + 1
            self.repository.update_run_counts(run_id, total, passed, failed, errors)

        return result

    def get_test_results(self, run_id: str, principal: Principal) -> List[TestResult]:
        """Get all test results for a run.

        Args:
            run_id: Run ID
            principal: Principal requesting the results

        Returns:
            List of TestResult objects
        """
        self.auth.authorize(principal, "read", "run")
        return self.repository.get_test_results(run_id)

    # ==================== Reporting ====================

    def generate_report(
        self,
        run_id: str,
        principal: Principal,
        format: str = "markdown",
    ) -> str:
        """Generate a report for a run.

        Args:
            run_id: Run ID
            principal: Principal requesting the report
            format: Report format (markdown, json, html)

        Returns:
            Report content
        """
        self.auth.authorize(principal, "read", "report")

        run = self.get_run(run_id, principal)
        results = self.get_test_results(run_id, principal)
        scope = self.get_scope(run.scope_id, principal)
        target = self.get_target(run.target_id, principal)

        if format == "markdown":
            return self._generate_markdown_report(run, results, scope, target)
        elif format == "json":
            import json

            return json.dumps(
                {
                    "run": run.to_dict(),
                    "results": [r.to_dict() for r in results],
                    "scope": scope.to_dict(),
                    "target": {
                        "id": target.id,
                        "name": target.name,
                        "type": target.type,
                    },
                },
                indent=2,
            )
        else:
            raise ValueError(f"Unknown report format: {format}")

    def _generate_markdown_report(
        self,
        run: Run,
        results: List[TestResult],
        scope: Scope,
        target: Target,
    ) -> str:
        """Generate a markdown report."""
        summary = run.score_summary or ScoreSummary()

        report = f"""# Aegis Security Assessment Report

## Overview

| Property | Value |
|----------|-------|
| Run ID | `{run.id}` |
| Target | {target.name} ({target.type}) |
| Pack | {run.pack_id} v{run.pack_version} |
| Scope | {scope.name} |
| Status | {run.status} |
| Started | {run.started_at or 'N/A'} |
| Completed | {run.completed_at or 'N/A'} |

## Summary

| Metric | Count |
|--------|-------|
| Total Tests | {summary.total_tests} |
| Passed | {summary.passed} |
| Failed | {summary.failed} |
| Errors | {summary.errors} |
| Skipped | {summary.skipped} |

### Findings by Severity

| Severity | Count |
|----------|-------|
| Critical | {summary.critical_findings} |
| High | {summary.high_findings} |
| Medium | {summary.medium_findings} |
| Low | {summary.low_findings} |
| Info | {summary.info_findings} |

## Detailed Results

"""
        # Group by status
        failed = [r for r in results if r.status == TestStatus.FAILED.value]
        passed = [r for r in results if r.status == TestStatus.PASSED.value]

        if failed:
            report += "### Vulnerabilities Found\n\n"
            for r in failed:
                report += f"""#### {r.test_case_id}

- **Severity:** {r.severity}
- **Susceptibility:** {r.susceptibility}
- **Observation:** {r.observation or 'N/A'}
- **Evidence:** {r.evidence_path or 'N/A'}

"""

        if passed:
            report += f"### Tests Passed ({len(passed)})\n\n"
            for r in passed[:10]:  # Limit to first 10
                report += f"- {r.test_case_id}\n"
            if len(passed) > 10:
                report += f"- ... and {len(passed) - 10} more\n"

        report += """
---

*Report generated by Aegis AI Security Testing Platform*
"""
        return report

    def _calculate_summary(self, results: List[TestResult]) -> ScoreSummary:
        """Calculate score summary from results."""
        summary = ScoreSummary()
        summary.total_tests = len(results)

        for r in results:
            if r.status == TestStatus.PASSED.value:
                summary.passed += 1
            elif r.status == TestStatus.FAILED.value:
                summary.failed += 1
                # Count by severity
                if r.severity == "critical":
                    summary.critical_findings += 1
                elif r.severity == "high":
                    summary.high_findings += 1
                elif r.severity == "medium":
                    summary.medium_findings += 1
                elif r.severity == "low":
                    summary.low_findings += 1
                else:
                    summary.info_findings += 1
            elif r.status == TestStatus.ERROR.value:
                summary.errors += 1
            elif r.status == TestStatus.SKIPPED.value:
                summary.skipped += 1

        # Calculate overall score (0-100)
        if summary.total_tests > 0:
            # Weight vulnerabilities by severity
            weighted_failures = (
                summary.critical_findings * 10
                + summary.high_findings * 5
                + summary.medium_findings * 2
                + summary.low_findings * 1
            )
            max_weighted = summary.total_tests * 10
            summary.overall_score = max(
                0, 100 - (weighted_failures / max_weighted * 100)
            )
        else:
            summary.overall_score = 100.0

        return summary

    # ==================== Audit ====================

    def get_audit_log(
        self,
        principal: Principal,
        run_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get audit log entries.

        Args:
            principal: Principal requesting the log
            run_id: Optional run filter
            limit: Maximum entries

        Returns:
            List of audit entry dictionaries
        """
        self.auth.authorize(principal, "read", "audit")

        if run_id:
            entries = self.audit.get_entries_for_run(run_id)
        else:
            entries = self.audit.get_entries_for_principal(principal.id, limit)

        return [e.to_dict() for e in entries]

    def verify_audit_integrity(
        self, principal: Principal
    ) -> Dict[str, Any]:
        """Verify integrity of the audit log.

        Args:
            principal: Principal requesting verification

        Returns:
            Verification result
        """
        self.auth.authorize(principal, "read", "audit")

        public_key = self._audit_key.public_key()
        is_valid, errors = self.audit.verify_integrity(public_key)

        return {
            "valid": is_valid,
            "errors": errors,
            "entries_checked": len(self.repository.get_all_audit_entries()),
        }

    # ==================== Additional API Methods ====================

    def list_scopes(self, principal: Principal) -> List[Scope]:
        """List all scopes.

        Args:
            principal: Principal requesting the list

        Returns:
            List of Scope objects
        """
        self.auth.authorize(principal, "read", "scope")
        return self.repository.list_scopes()

    def approve_scope(
        self,
        scope_id: str,
        signature: str,
        principal: Principal,
        comment: Optional[str] = None,
    ) -> Scope:
        """Approve a scope with Ed25519 signature.

        Args:
            scope_id: Scope to approve
            signature: Base64-encoded Ed25519 signature of scope hash
            principal: Principal providing approval
            comment: Optional approval comment

        Returns:
            Updated Scope object
        """
        from aegis.core.models import Approval

        scope = self.get_scope(scope_id, principal)

        # Create approval
        approval = Approval(
            approver_id=principal.id,
            signature=signature,
            public_key_fingerprint=principal.public_key_fingerprint or "",
            approved_at=datetime.utcnow(),
            comment=comment,
        )

        # Add to scope
        scope.approvals.append(approval)
        self.repository.update_scope_approvals(scope_id, scope.approvals)

        # Audit
        self.audit.log(
            principal_id=principal.id,
            action="scope.approve",
            target=scope_id,
            scope_id=scope_id,
            details={"comment": comment},
        )

        logger.info(f"Scope {scope_id} approved by {principal.id}")
        return self.get_scope(scope_id, principal)

    def list_packs(self) -> List["Pack"]:
        """List all loaded packs.

        Returns:
            List of Pack objects
        """
        return list(self._packs.values())

    def get_pack(self, pack_id: str) -> "Pack":
        """Get a pack by ID.

        Args:
            pack_id: Pack ID

        Returns:
            Pack object
        """
        from aegis.core.exceptions import PackNotFoundError

        pack = self._packs.get(pack_id)
        if not pack:
            raise PackNotFoundError(f"Pack {pack_id} not found")
        return pack

    def load_pack(self, pack: "Pack") -> None:
        """Load a pack into the engine.

        Args:
            pack: Pack to load
        """
        self._packs[pack.name] = pack
        logger.info(f"Loaded pack: {pack.name} v{pack.version}")

    def create_principal(
        self,
        name: str,
        roles: List[str],
        admin: Principal,
    ) -> tuple:
        """Create a new principal.

        Args:
            name: Principal name
            roles: List of role names
            admin: Admin principal creating this principal

        Returns:
            Tuple of (Principal, api_key)
        """
        if not admin.is_admin():
            raise AuthorizationError("Only admins can create principals")

        import secrets

        principal = Principal(
            id=str(uuid.uuid4()),
            name=name,
            roles=roles,
            api_key_hash="",  # Will be set below
            created_at=datetime.utcnow(),
        )

        # Generate API key
        api_key = self.auth.create_api_key(principal.id)
        principal.api_key_hash = AuthService.hash_api_key(api_key)

        self.repository.save_principal(principal)

        # Audit
        self.audit.log(
            principal_id=admin.id,
            action="principal.create",
            target=principal.id,
            details={"name": name, "roles": roles},
        )

        logger.info(f"Created principal {principal.id} by admin {admin.id}")
        return principal, api_key

    def list_principals(self, principal: Principal) -> List[Principal]:
        """List all principals.

        Args:
            principal: Principal requesting the list (must be admin)

        Returns:
            List of Principal objects
        """
        if not principal.is_admin():
            raise AuthorizationError("Only admins can list principals")
        return self.repository.get_all_principals()

    def register_public_key(
        self,
        principal_id: str,
        public_key_pem: str,
        admin: Principal,
    ) -> Principal:
        """Register a public key for a principal.

        Args:
            principal_id: Principal to register key for
            public_key_pem: PEM-encoded Ed25519 public key
            admin: Admin performing registration

        Returns:
            Updated Principal
        """
        from cryptography.hazmat.primitives import serialization

        if not admin.is_admin():
            raise AuthorizationError("Only admins can register public keys")

        # Load PEM key
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("Only Ed25519 public keys are supported")

        # Register via keystore
        fingerprint = self.keystore.register_key(
            principal=self.repository.get_principal(principal_id),
            public_key=public_key,
            registering_admin=admin,
        )

        return self.repository.get_principal(principal_id)

    def revoke_principal(self, principal_id: str, admin: Principal) -> None:
        """Revoke a principal's access.

        Args:
            principal_id: Principal to revoke
            admin: Admin performing revocation
        """
        if not admin.is_admin():
            raise AuthorizationError("Only admins can revoke principals")

        self.repository.revoke_principal(principal_id)

        # Audit
        self.audit.log(
            principal_id=admin.id,
            action="principal.revoke",
            target=principal_id,
        )

        logger.info(f"Revoked principal {principal_id} by admin {admin.id}")

    def list_audit_entries(
        self,
        principal: Principal,
        principal_id_filter: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Any]:
        """List audit log entries.

        Args:
            principal: Principal requesting entries (must be auditor)
            principal_id_filter: Filter by principal
            action: Filter by action
            resource_type: Filter by resource type
            since: Filter entries since this time
            limit: Maximum entries to return

        Returns:
            List of AuditEntry objects
        """
        self.auth.authorize(principal, "read", "audit")

        entries = self.repository.get_all_audit_entries()

        # Apply filters
        if principal_id_filter:
            entries = [e for e in entries if e.principal_id == principal_id_filter]
        if action:
            entries = [e for e in entries if e.action == action]
        if resource_type:
            entries = [e for e in entries if e.resource_type == resource_type]
        if since:
            entries = [e for e in entries if e.timestamp >= since]

        return entries[:limit]
