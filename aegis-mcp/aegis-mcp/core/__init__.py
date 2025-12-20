"""Aegis MCP Core Module"""
from .config import (
    SERVICE_NAME,
    VERSION,
    PORT,
    HOST,
    STEALTH_PROFILES,
    SUPPORTED_PROVIDERS,
    CREDENTIALS,
    get_stealth_config,
    check_credentials
)

__all__ = [
    "SERVICE_NAME",
    "VERSION", 
    "PORT",
    "HOST",
    "STEALTH_PROFILES",
    "SUPPORTED_PROVIDERS",
    "CREDENTIALS",
    "get_stealth_config",
    "check_credentials"
]
