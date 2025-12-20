"""
Aegis MCP Adaptive Payload Generation Module

Context-aware payload generation based on target fingerprinting.
Adapts shells, webshells, and injections to detected defenses.
"""

from .templates import REVERSE_SHELLS, WEBSHELLS, WAF_BYPASS, AV_EVASION
from .adaptive import AdaptivePayloadGenerator
from .selector import PayloadSelector

__all__ = [
    "REVERSE_SHELLS",
    "WEBSHELLS", 
    "WAF_BYPASS",
    "AV_EVASION",
    "AdaptivePayloadGenerator",
    "PayloadSelector",
]
