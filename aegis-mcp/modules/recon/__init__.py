"""
Aegis MCP Reconnaissance Module
Autonomous target mapping and attack surface discovery.

Usage:
    from recon import AutonomousRecon, quick_enum, full_enum, stealth_enum
    
    # Quick recon
    results = quick_enum("target.com")
    
    # Full recon with JS analysis
    results = full_enum("target.com")
    
    # Stealth mode
    results = stealth_enum("target.com")
    
    # Custom pipeline
    recon = AutonomousRecon(threads=50, stealth=True)
    results = recon.full_recon("target.com", deep_dns=True, analyze_js=True)
    
    # Export targets for other tools
    targets = recon.export_targets()
"""

from .dns_enum import DNSEnumerator, quick_enum as dns_quick, deep_enum as dns_deep
from .http_probe import HTTPProber, quick_probe, stealth_probe
from .content_analyzer import ContentAnalyzer, JSAnalyzer, analyze_page, analyze_js_files
from .autonomous import (
    AutonomousRecon, 
    quick_enum, 
    full_enum, 
    stealth_enum
)

__all__ = [
    # Main classes
    "AutonomousRecon",
    "DNSEnumerator", 
    "HTTPProber",
    "ContentAnalyzer",
    "JSAnalyzer",
    
    # Quick functions
    "quick_enum",
    "full_enum", 
    "stealth_enum",
    "dns_quick",
    "dns_deep",
    "quick_probe",
    "stealth_probe",
    "analyze_page",
    "analyze_js_files",
]

# MCP Tool Registration Schema
MCP_TOOLS = [
    {
        "name": "recon_autonomous",
        "description": "Full autonomous reconnaissance against a domain. Combines DNS enumeration, HTTP probing, content analysis, and JS analysis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain to recon"
                },
                "mode": {
                    "type": "string",
                    "enum": ["quick", "full", "stealth"],
                    "default": "full",
                    "description": "Recon mode: quick (fast), full (thorough), stealth (slow/evasive)"
                },
                "deep_dns": {
                    "type": "boolean",
                    "default": True,
                    "description": "Use multiple DNS sources"
                },
                "analyze_js": {
                    "type": "boolean", 
                    "default": True,
                    "description": "Analyze discovered JavaScript files"
                },
                "max_hosts": {
                    "type": "integer",
                    "default": 100,
                    "description": "Maximum hosts to probe"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "recon_dns",
        "description": "DNS enumeration only - subdomain discovery and record collection",
        "inputSchema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain"
                },
                "deep": {
                    "type": "boolean",
                    "default": True,
                    "description": "Use multiple data sources"
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "recon_http_probe",
        "description": "HTTP probe hosts for technology fingerprinting",
        "inputSchema": {
            "type": "object",
            "properties": {
                "targets": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of hosts/URLs to probe"
                },
                "stealth": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable stealth mode with delays"
                }
            },
            "required": ["targets"]
        }
    },
    {
        "name": "recon_content_analyze",
        "description": "Analyze page content for endpoints, parameters, and secrets",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL to analyze"
                }
            },
            "required": ["url"]
        }
    }
]


def handle_mcp_call(tool_name: str, params: dict) -> dict:
    """Handle MCP tool calls for recon module."""
    
    if tool_name == "recon_autonomous":
        mode = params.get("mode", "full")
        domain = params["domain"]
        
        if mode == "quick":
            return quick_enum(domain)
        elif mode == "stealth":
            return stealth_enum(domain)
        else:
            recon = AutonomousRecon()
            return recon.full_recon(
                domain,
                deep_dns=params.get("deep_dns", True),
                analyze_js=params.get("analyze_js", True),
                max_hosts=params.get("max_hosts", 100)
            )
    
    elif tool_name == "recon_dns":
        enum = DNSEnumerator()
        return enum.enumerate(params["domain"], deep=params.get("deep", True))
    
    elif tool_name == "recon_http_probe":
        targets = params["targets"]
        if params.get("stealth"):
            return stealth_probe(targets)
        return quick_probe(targets)
    
    elif tool_name == "recon_content_analyze":
        return analyze_page(params["url"])
    
    else:
        return {"error": f"Unknown tool: {tool_name}"}
