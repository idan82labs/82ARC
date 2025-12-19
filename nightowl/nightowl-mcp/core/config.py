"""
NIGHTOWL Core Configuration
"""
import os
from pathlib import Path

# Service Identity
SERVICE_NAME = "nightowl"
VERSION = "1.0.0"

# Paths
BASE_DIR = Path(__file__).parent.parent
MODULES_DIR = BASE_DIR.parent / "modules"

# Server Config
PORT = int(os.environ.get("PORT", 8080))
HOST = os.environ.get("HOST", "0.0.0.0")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

# Stealth Profiles
STEALTH_PROFILES = {
    1: {
        "name": "loud",
        "scan_threads": 50,
        "delay_ms": 0,
        "jitter": False
    },
    3: {
        "name": "balanced",
        "scan_threads": 10,
        "delay_ms": 500,
        "jitter": True
    },
    5: {
        "name": "paranoid",
        "scan_threads": 2,
        "delay_ms": 5000,
        "jitter": True,
        "proxy_rotation": True
    }
}

# Infrastructure Providers
SUPPORTED_PROVIDERS = ["digitalocean", "vultr", "linode", "aws"]
DEFAULT_PROVIDER = "digitalocean"

# Credentials (from environment)
CREDENTIALS = {
    "digitalocean": os.environ.get("DIGITALOCEAN_TOKEN"),
    "vultr": os.environ.get("VULTR_API_KEY"),
    "linode": os.environ.get("LINODE_TOKEN"),
    "cloudflare_token": os.environ.get("CLOUDFLARE_TOKEN"),
    "cloudflare_zone": os.environ.get("CLOUDFLARE_ZONE_ID")
}

# Default callback configuration
DEFAULT_CALLBACK_PORT = 443
CALLBACK_PROTOCOLS = ["http", "https", "dns", "icmp"]

# Operation Settings
MAX_CONCURRENT_OPERATIONS = 5
OPERATION_TIMEOUT_HOURS = 24
AUTO_BURN_ON_TIMEOUT = True

# AI Attack Settings
JAILBREAK_TECHNIQUES = [
    "dan", "roleplay", "hypothetical", "translation", 
    "encoding", "context_manipulation", "instruction_hierarchy", "crescendo"
]
INJECTION_TECHNIQUES = [
    "direct", "delimiter_escape", "context_overflow", 
    "indirect", "data_exfiltration", "instruction_override"
]

def get_stealth_config(level: int) -> dict:
    """Get stealth configuration for given level (1-5)."""
    # Clamp to valid range
    level = max(1, min(5, level))
    # Find nearest defined profile
    if level in STEALTH_PROFILES:
        return STEALTH_PROFILES[level]
    # Interpolate between levels
    lower = max(k for k in STEALTH_PROFILES.keys() if k <= level)
    return STEALTH_PROFILES[lower]

def check_credentials(provider: str = None) -> dict:
    """Check which credentials are configured."""
    if provider:
        return {provider: bool(CREDENTIALS.get(provider))}
    return {k: bool(v) for k, v in CREDENTIALS.items()}
