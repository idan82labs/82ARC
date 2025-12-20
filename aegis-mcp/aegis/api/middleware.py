"""Authentication middleware for Aegis API.

Implements API key authentication with bearer token support.
"""

import logging
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from aegis.core import AuthService, Principal
from aegis.core.exceptions import AuthenticationError, AuthorizationError

logger = logging.getLogger(__name__)

# HTTP Bearer security scheme
security = HTTPBearer(auto_error=False)


class AuthMiddleware:
    """Authentication middleware for FastAPI."""

    def __init__(self, auth_service: AuthService):
        """Initialize middleware with auth service.

        Args:
            auth_service: Authentication service instance
        """
        self.auth_service = auth_service

    async def get_current_principal(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    ) -> Principal:
        """Extract and validate principal from request.

        Supports:
        - Bearer token in Authorization header
        - X-API-Key header

        Args:
            request: FastAPI request
            credentials: HTTP Bearer credentials

        Returns:
            Authenticated Principal

        Raises:
            HTTPException: If authentication fails
        """
        api_key: Optional[str] = None

        # Try Bearer token first
        if credentials and credentials.scheme.lower() == "bearer":
            api_key = credentials.credentials

        # Fall back to X-API-Key header
        if not api_key:
            api_key = request.headers.get("X-API-Key")

        if not api_key:
            logger.warning("No API key provided in request")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing API key. Use Authorization: Bearer <key> or X-API-Key header",
                headers={"WWW-Authenticate": "Bearer"},
            )

        try:
            principal = self.auth_service.authenticate_api_key(api_key)
            # Store in request state for downstream use
            request.state.principal = principal
            return principal
        except AuthenticationError as e:
            logger.warning(f"Authentication failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e),
                headers={"WWW-Authenticate": "Bearer"},
            )

    def require_permission(self, operation: str, resource: str):
        """Create a dependency that checks for specific permission.

        Args:
            operation: Operation type (create, read, update, delete)
            resource: Resource type (run, scope, report, etc.)

        Returns:
            Dependency function
        """
        async def check_permission(
            principal: Principal = Depends(self.get_current_principal),
        ) -> Principal:
            try:
                self.auth_service.authorize(principal, operation, resource)
                return principal
            except AuthorizationError as e:
                logger.warning(f"Authorization failed: {e}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=str(e),
                )

        return check_permission

    def require_admin(self):
        """Create a dependency that requires admin role.

        Returns:
            Dependency function
        """
        async def check_admin(
            principal: Principal = Depends(self.get_current_principal),
        ) -> Principal:
            if not principal.is_admin():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Admin role required",
                )
            return principal

        return check_admin


def get_auth_middleware(request: Request) -> AuthMiddleware:
    """Get auth middleware from request state.

    Args:
        request: FastAPI request

    Returns:
        AuthMiddleware instance
    """
    return request.app.state.auth_middleware
