"""Audit logging with cryptographic integrity.

Implements:
- Hash chain for tamper detection
- Ed25519 signatures on entries
- Append-only enforcement
"""

import base64
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.exceptions import InvalidSignature

from aegis.core.redaction import RedactionService

if TYPE_CHECKING:
    from aegis.core.repository import Repository

logger = logging.getLogger(__name__)


@dataclass
class AuditEntry:
    """Single entry in the audit log."""

    id: str
    timestamp: datetime
    principal_id: str
    action: str
    target: Optional[str] = None
    outcome: str = "success"
    run_id: Optional[str] = None
    scope_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    previous_hash: Optional[str] = None
    entry_hash: Optional[str] = None
    signature: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "principal_id": self.principal_id,
            "action": self.action,
            "target": self.target,
            "outcome": self.outcome,
            "run_id": self.run_id,
            "scope_id": self.scope_id,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "entry_hash": self.entry_hash,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuditEntry":
        return cls(
            id=data["id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            principal_id=data["principal_id"],
            action=data["action"],
            target=data.get("target"),
            outcome=data.get("outcome", "success"),
            run_id=data.get("run_id"),
            scope_id=data.get("scope_id"),
            details=data.get("details"),
            previous_hash=data.get("previous_hash"),
            entry_hash=data.get("entry_hash"),
            signature=data.get("signature"),
        )


class AuditLogger:
    """Append-only audit log with hash chain and signatures."""

    def __init__(
        self,
        repository: "Repository",
        signing_key: Ed25519PrivateKey,
        redaction: Optional[RedactionService] = None,
    ):
        """Initialize audit logger.

        Args:
            repository: Repository for audit storage
            signing_key: Ed25519 private key for signing entries
            redaction: Optional redaction service for details
        """
        self.repository = repository
        self.signing_key = signing_key
        self.redaction = redaction or RedactionService()
        self._last_hash = self._get_last_hash()

    def _get_last_hash(self) -> Optional[str]:
        """Get hash of last audit entry."""
        last_entry = self.repository.get_last_audit_entry()
        return last_entry.entry_hash if last_entry else None

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

    def log(
        self,
        principal_id: str,
        action: str,
        target: Optional[str] = None,
        outcome: str = "success",
        run_id: Optional[str] = None,
        scope_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEntry:
        """Append signed entry to audit log.

        Args:
            principal_id: ID of actor
            action: Action performed
            target: Target of action
            outcome: Result (success, failure, error)
            run_id: Associated run ID
            scope_id: Associated scope ID
            details: Additional details (will be redacted)

        Returns:
            Created audit entry
        """
        import uuid

        entry = AuditEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.utcnow(),
            principal_id=principal_id,
            action=action,
            target=target,
            outcome=outcome,
            run_id=run_id,
            scope_id=scope_id,
            details=details,
        )

        # Redact details before logging
        if entry.details:
            entry.details = self.redaction.redact_dict(
                entry.details, list(entry.details.keys())
            )

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

        logger.debug(
            f"Audit: {action} by {principal_id} -> {outcome} (hash: {entry.entry_hash[:16]}...)"
        )

        return entry

    def verify_integrity(
        self, public_key: Ed25519PublicKey
    ) -> Tuple[bool, List[str]]:
        """Verify hash chain and all signatures.

        Args:
            public_key: Ed25519 public key for signature verification

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
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
            if entry.signature:
                try:
                    public_key.verify(
                        base64.b64decode(entry.signature),
                        entry.entry_hash.encode(),
                    )
                except InvalidSignature:
                    errors.append(f"Invalid signature at entry {i}")
            else:
                errors.append(f"Missing signature at entry {i}")

            prev_hash = entry.entry_hash

        is_valid = len(errors) == 0
        if is_valid:
            logger.info(f"Audit log integrity verified ({len(entries)} entries)")
        else:
            logger.error(f"Audit log integrity check failed: {len(errors)} errors")

        return is_valid, errors

    def export_for_compliance(
        self,
        start_date: datetime,
        end_date: datetime,
        format: str = "json",
    ) -> str:
        """Export audit log entries for compliance review.

        Args:
            start_date: Start of range
            end_date: End of range
            format: Output format ("json" or "csv")

        Returns:
            Formatted export string
        """
        import json

        entries = self.repository.get_audit_entries_in_range(start_date, end_date)

        if format == "json":
            return json.dumps([e.to_dict() for e in entries], indent=2)
        elif format == "csv":
            lines = ["timestamp,principal_id,action,target,outcome,entry_hash"]
            for e in entries:
                lines.append(
                    f'"{e.timestamp.isoformat()}","{e.principal_id}",'
                    f'"{e.action}","{e.target or ""}","{e.outcome}","{e.entry_hash}"'
                )
            return "\n".join(lines)
        else:
            raise ValueError(f"Unknown format: {format}")

    def get_entries_for_run(self, run_id: str) -> List[AuditEntry]:
        """Get all audit entries for a specific run.

        Args:
            run_id: Run ID to filter by

        Returns:
            List of audit entries
        """
        return self.repository.get_audit_entries_for_run(run_id)

    def get_entries_for_principal(
        self, principal_id: str, limit: int = 100
    ) -> List[AuditEntry]:
        """Get recent audit entries for a principal.

        Args:
            principal_id: Principal ID to filter by
            limit: Maximum entries to return

        Returns:
            List of audit entries
        """
        return self.repository.get_audit_entries_for_principal(principal_id, limit)
