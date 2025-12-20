"""Authentication and authorization for Aegis.

Implements:
- bcrypt API key hashing
- Role-based authorization
- Ed25519 public key trust model
"""

import base64
import hashlib
import logging
import secrets
from datetime import datetime
from typing import Dict, List, Optional, TYPE_CHECKING

import bcrypt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

from aegis.core.exceptions import AuthenticationError, AuthorizationError
from aegis.core.models import Principal

if TYPE_CHECKING:
    from aegis.core.repository import Repository

logger = logging.getLogger(__name__)


class AuthService:
    """Authentication service for all interfaces."""

    # bcrypt work factor (2^12 = 4096 iterations, ~250ms on modern hardware)
    BCRYPT_ROUNDS = 12

    # Role permissions
    ROLE_PERMISSIONS = {
        "admin": ["*"],
        "operator": [
            "run:create",
            "run:read",
            "run:abort",
            "scope:read",
            "target:read",
            "report:read",
            "report:create",
        ],
        "auditor": [
            "run:read",
            "scope:read",
            "report:read",
            "audit:read",
        ],
    }

    def __init__(self, repository: "Repository"):
        """Initialize authentication service.

        Args:
            repository: Repository for principal storage
        """
        self.repository = repository

    @classmethod
    def hash_api_key(cls, api_key: str) -> str:
        """Hash API key using bcrypt with automatic salt.

        Args:
            api_key: Plaintext API key

        Returns:
            bcrypt hash string
        """
        return bcrypt.hashpw(
            api_key.encode(), bcrypt.gensalt(rounds=cls.BCRYPT_ROUNDS)
        ).decode()

    @classmethod
    def verify_api_key(cls, api_key: str, stored_hash: str) -> bool:
        """Verify API key against bcrypt hash.

        Args:
            api_key: Plaintext API key to verify
            stored_hash: bcrypt hash from storage

        Returns:
            True if match, False otherwise
        """
        try:
            return bcrypt.checkpw(api_key.encode(), stored_hash.encode())
        except Exception:
            return False

    def authenticate_api_key(self, api_key: str) -> Principal:
        """Authenticate via API key.

        Args:
            api_key: API key to authenticate

        Returns:
            Authenticated Principal

        Raises:
            AuthenticationError: If authentication fails
        """
        # Get all principals and check bcrypt hash
        # Note: In production with many users, use indexed prefix lookup
        principals = self.repository.get_all_principals()
        for principal in principals:
            if self.verify_api_key(api_key, principal.api_key_hash):
                if principal.is_revoked:
                    raise AuthenticationError("API key revoked")
                self.repository.update_last_active(principal.id)
                return principal
        raise AuthenticationError("Invalid API key")

    def create_api_key(self, principal_id: str) -> str:
        """Generate new API key and store bcrypt hash.

        Args:
            principal_id: ID of principal to create key for

        Returns:
            Plaintext API key (only returned once, never stored)
        """
        api_key = f"aegis_{secrets.token_urlsafe(32)}"
        key_hash = self.hash_api_key(api_key)
        self.repository.update_principal_key_hash(principal_id, key_hash)
        logger.info(f"Created new API key for principal {principal_id}")
        return api_key

    def authorize(
        self, principal: Principal, operation: str, resource: str
    ) -> bool:
        """Check if principal can perform operation on resource.

        Args:
            principal: Authenticated principal
            operation: Operation type (create, read, update, delete, abort)
            resource: Resource type (run, scope, target, report, audit)

        Returns:
            True if authorized

        Raises:
            AuthorizationError: If not authorized
        """
        required = f"{operation}:{resource}"
        for role in principal.roles:
            permissions = self.ROLE_PERMISSIONS.get(role, [])
            if "*" in permissions:
                return True
            if required in permissions:
                return True
        raise AuthorizationError(
            f"Principal {principal.id} cannot {operation} on {resource}"
        )

    def get_permissions(self, principal: Principal) -> List[str]:
        """Get all permissions for a principal.

        Args:
            principal: Principal to get permissions for

        Returns:
            List of permission strings
        """
        permissions = set()
        for role in principal.roles:
            role_perms = self.ROLE_PERMISSIONS.get(role, [])
            if "*" in role_perms:
                # Admin has all permissions
                all_perms = []
                for perms in self.ROLE_PERMISSIONS.values():
                    all_perms.extend(p for p in perms if p != "*")
                return list(set(all_perms))
            permissions.update(role_perms)
        return list(permissions)


class TrustedKeyStore:
    """Manages trusted public keys for approval verification."""

    def __init__(self, repository: "Repository"):
        """Initialize key store.

        Args:
            repository: Repository for key storage
        """
        self.repository = repository
        self._cache: Dict[str, Ed25519PublicKey] = {}

    def register_key(
        self,
        principal: Principal,
        public_key: Ed25519PublicKey,
        registering_admin: Principal,
    ) -> str:
        """Register a public key for a principal. Requires admin.

        Args:
            principal: Principal to register key for
            public_key: Ed25519 public key
            registering_admin: Admin performing registration

        Returns:
            Key fingerprint (SHA256)

        Raises:
            AuthorizationError: If registering_admin is not admin
        """
        if not registering_admin.is_admin():
            raise AuthorizationError("Only admins can register public keys")

        # Compute fingerprint
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = hashlib.sha256(public_bytes).hexdigest()

        # Store in principal record
        self.repository.update_principal_public_key(
            principal.id, public_bytes, fingerprint
        )

        # Clear cache
        self._cache.pop(principal.id, None)

        logger.info(
            f"Registered public key for {principal.id} "
            f"(fingerprint: {fingerprint[:16]}...) "
            f"by admin {registering_admin.id}"
        )

        return fingerprint

    def get_trusted_key(self, principal_id: str) -> Optional[Ed25519PublicKey]:
        """Get trusted public key for a principal.

        Args:
            principal_id: Principal ID

        Returns:
            Ed25519 public key or None if not found
        """
        if principal_id in self._cache:
            return self._cache[principal_id]

        principal = self.repository.get_principal(principal_id)
        if not principal or not principal.public_key:
            return None

        # Load and cache
        key = Ed25519PublicKey.from_public_bytes(principal.public_key)
        self._cache[principal_id] = key
        return key

    def verify_fingerprint(
        self, principal_id: str, expected_fingerprint: str
    ) -> bool:
        """Verify public key fingerprint matches stored key.

        Args:
            principal_id: Principal ID
            expected_fingerprint: Expected fingerprint

        Returns:
            True if match, False otherwise
        """
        principal = self.repository.get_principal(principal_id)
        if not principal:
            return False
        return principal.public_key_fingerprint == expected_fingerprint

    def revoke_key(
        self, principal_id: str, revoking_admin: Principal
    ) -> None:
        """Revoke a principal's public key. Requires admin.

        Args:
            principal_id: Principal ID to revoke key for
            revoking_admin: Admin performing revocation

        Raises:
            AuthorizationError: If revoking_admin is not admin
        """
        if not revoking_admin.is_admin():
            raise AuthorizationError("Only admins can revoke public keys")

        self.repository.update_principal_public_key(principal_id, None, None)
        self._cache.pop(principal_id, None)

        logger.warning(
            f"Revoked public key for {principal_id} by admin {revoking_admin.id}"
        )

    def clear_cache(self) -> None:
        """Clear the key cache."""
        self._cache.clear()
