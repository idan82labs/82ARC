"""Custom exceptions for Aegis."""

from typing import Optional


class AegisError(Exception):
    """Base exception for all Aegis errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


# Authentication/Authorization Errors
class AuthenticationError(AegisError):
    """Failed to authenticate principal."""

    pass


class AuthorizationError(AegisError):
    """Principal not authorized for operation."""

    pass


class UnauthorizedOperatorError(AuthorizationError):
    """Principal is not an operator."""

    pass


# Scope Errors
class ScopeError(AegisError):
    """Base class for scope-related errors."""

    pass


class ScopeExpiredError(ScopeError):
    """Scope has expired."""

    pass


class ScopeNotFoundError(ScopeError):
    """Scope not found."""

    pass


class TargetNotAuthorizedError(ScopeError):
    """Target not in scope's authorized list."""

    pass


class OutsideTimeWindowError(ScopeError):
    """Operation attempted outside allowed time window."""

    pass


class RateLimitExceededError(ScopeError):
    """Scope's request limit exceeded."""

    pass


class TestCaseRestrictedError(ScopeError):
    """Test case blocked by scope restrictions."""

    pass


class InsufficientApprovalsError(ScopeError):
    """Scope does not have enough valid approvals."""

    pass


# Pack Errors
class PackError(AegisError):
    """Base class for pack-related errors."""

    pass


class PackNotFoundError(PackError):
    """Pack not found."""

    pass


class InvalidPackError(PackError):
    """Pack failed validation."""

    pass


class UnknownExecutorError(PackError):
    """Referenced executor not registered."""

    pass


# Storage Errors
class StorageError(AegisError):
    """Base class for storage-related errors."""

    pass


class PathValidationError(StorageError):
    """Path validation failed (traversal attempt, invalid chars)."""

    pass


class SecurityError(AegisError):
    """Security constraint violation."""

    pass


# Run Errors
class RunError(AegisError):
    """Base class for run-related errors."""

    pass


class RunNotFoundError(RunError):
    """Run not found."""

    pass


class RunAlreadyExistsError(RunError):
    """Run with this ID already exists."""

    pass


class RunStateError(RunError):
    """Invalid run state transition."""

    pass
