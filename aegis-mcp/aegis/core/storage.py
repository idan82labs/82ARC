"""Secure storage utilities for Aegis.

Implements:
- Path traversal protection
- Encryption at rest
- Secure file operations
"""

import base64
import logging
import os
import re
from pathlib import Path
from typing import IO, Any, Dict, List, Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from aegis.core.exceptions import PathValidationError, SecurityError

logger = logging.getLogger(__name__)


class SecurePath:
    """Secure path handling with traversal protection."""

    # Only allow alphanumeric, dash, underscore in path components
    SAFE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
    MAX_COMPONENT_LENGTH = 64

    def __init__(self, base_path: Path):
        """Initialize with base path.

        Args:
            base_path: Base directory that all paths must be under
        """
        self.base = base_path.resolve()
        self.base.mkdir(parents=True, exist_ok=True)

    def validate_component(self, component: str) -> str:
        """Validate a single path component (e.g., run_id, test_id).

        Args:
            component: Path component to validate

        Returns:
            The validated component

        Raises:
            PathValidationError: If component is invalid
        """
        if not component:
            raise PathValidationError("Empty path component")

        if not self.SAFE_PATTERN.match(component):
            raise PathValidationError(
                f"Invalid characters in path component: {component}"
            )

        if component in (".", ".."):
            raise PathValidationError("Directory traversal attempt detected")

        if len(component) > self.MAX_COMPONENT_LENGTH:
            raise PathValidationError(
                f"Path component too long: {len(component)} > {self.MAX_COMPONENT_LENGTH}"
            )

        return component

    def safe_join(self, *components: str) -> Path:
        """Safely join path components with traversal protection.

        Args:
            *components: Path components to join

        Returns:
            Resolved Path object

        Raises:
            PathValidationError: If path is invalid or escapes base
        """
        validated = [self.validate_component(c) for c in components]
        result = self.base.joinpath(*validated).resolve()

        # Final check: must still be under base
        if not str(result).startswith(str(self.base)):
            raise PathValidationError(f"Path escapes base directory: {result}")

        return result

    def safe_open(self, *components: str, mode: str = "r") -> IO:
        """Safely open a file with path validation.

        Args:
            *components: Path components
            mode: File open mode

        Returns:
            File handle

        Raises:
            PathValidationError: If path is invalid or is a symlink
        """
        path = self.safe_join(*components)

        # Additional safety: no symlinks
        if path.is_symlink():
            raise PathValidationError(f"Symlinks not allowed: {path}")

        return open(path, mode)

    def exists(self, *components: str) -> bool:
        """Check if path exists."""
        try:
            path = self.safe_join(*components)
            return path.exists()
        except PathValidationError:
            return False

    def mkdir(self, *components: str) -> Path:
        """Create directory with safe path."""
        path = self.safe_join(*components)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def remove(self, *components: str, secure: bool = True) -> bool:
        """Remove file, optionally with secure overwrite.

        Args:
            *components: Path components
            secure: If True, overwrite with random before delete

        Returns:
            True if removed, False if not found
        """
        try:
            path = self.safe_join(*components)
            if not path.exists():
                return False

            if path.is_file():
                if secure:
                    # Overwrite with random data before delete
                    size = path.stat().st_size
                    with open(path, "wb") as f:
                        f.write(os.urandom(size))
                path.unlink()
            elif path.is_dir():
                # Recursively remove directory
                for child in path.iterdir():
                    if child.is_file():
                        if secure:
                            size = child.stat().st_size
                            with open(child, "wb") as f:
                                f.write(os.urandom(size))
                        child.unlink()
                path.rmdir()
            return True
        except PathValidationError:
            return False


class DataEncryption:
    """Encryption at rest for sensitive data using Fernet (AES-128-CBC + HMAC)."""

    def __init__(
        self, key_path: Optional[Path] = None, master_password: Optional[str] = None
    ):
        """Initialize encryption.

        Args:
            key_path: Path to key file (will be created if doesn't exist)
            master_password: If provided, derive key from password
        """
        self.key_path = key_path
        self._fernet = self._load_or_create_key(master_password)

    def _load_or_create_key(self, master_password: Optional[str]) -> Fernet:
        """Load existing key or create new one."""
        if self.key_path and self.key_path.exists():
            # Verify file permissions (must be 0600)
            mode = self.key_path.stat().st_mode & 0o777
            if mode != 0o600:
                raise SecurityError(
                    f"Key file has insecure permissions: {oct(mode)}. "
                    f"Run: chmod 600 {self.key_path}"
                )
            key = self.key_path.read_bytes()
        else:
            # Generate new key
            if master_password:
                # Derive from password
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=480000,
                )
                key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            else:
                key = Fernet.generate_key()

            if self.key_path:
                # Save with secure permissions
                self.key_path.parent.mkdir(parents=True, exist_ok=True)
                self.key_path.touch(mode=0o600)
                self.key_path.write_bytes(key)
                logger.info(f"Created encryption key at {self.key_path}")

        return Fernet(key)

    def encrypt(self, data: str) -> str:
        """Encrypt string data, return base64-encoded ciphertext."""
        return self._fernet.encrypt(data.encode()).decode()

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt base64-encoded ciphertext to string."""
        return self._fernet.decrypt(ciphertext.encode()).decode()

    def encrypt_dict(
        self, data: Dict[str, Any], fields: List[str]
    ) -> Dict[str, Any]:
        """Encrypt specified fields in a dictionary.

        Args:
            data: Dictionary to encrypt
            fields: List of field names to encrypt

        Returns:
            New dictionary with encrypted fields marked
        """
        result = data.copy()
        for field in fields:
            if field in result and result[field] is not None:
                result[field] = self.encrypt(str(result[field]))
                result[f"{field}_encrypted"] = True
        return result

    def decrypt_dict(
        self, data: Dict[str, Any], fields: List[str]
    ) -> Dict[str, Any]:
        """Decrypt specified fields in a dictionary.

        Args:
            data: Dictionary with encrypted fields
            fields: List of field names to decrypt

        Returns:
            New dictionary with decrypted fields
        """
        result = data.copy()
        for field in fields:
            if data.get(f"{field}_encrypted") and field in result:
                result[field] = self.decrypt(result[field])
                del result[f"{field}_encrypted"]
        return result

    def is_encrypted(self, data: str) -> bool:
        """Check if data appears to be Fernet encrypted."""
        try:
            # Fernet tokens start with gAAAAA
            return data.startswith("gAAAAA") and len(data) > 50
        except Exception:
            return False
