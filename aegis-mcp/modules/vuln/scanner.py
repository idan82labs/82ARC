"""
Unified Vulnerability Scanner - Enhanced Edition

Comprehensive vulnerability scanning with support for:
- SQL Injection (error-based, blind, time-based, UNION)
- XSS (reflected, stored, DOM-based)
- SSRF (internal network, cloud metadata)
- SSTI (13+ template engines)
- XXE (classic, blind, error-based)
- LFI/Path Traversal (with RCE via log poisoning)
- JWT Attacks (none alg, weak secrets, kid injection)
- Insecure Deserialization (coming soon)

Based on OWASP Top 10, PortSwigger research, and real-world
penetration testing methodologies.
"""
from .sqli import SQLiScanner
from .xss import XSSScanner
from .ssrf import SSRFScanner
from .ssti import SSTIScanner
from .xxe import XXEScanner
from .lfi import LFIScanner
from .jwt import JWTScanner
from typing import List, Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
import json
import time


class ScanMode(Enum):
    """Scanning intensity modes."""
    QUICK = "quick"  # Fast scan, common payloads only
    STANDARD = "standard"  # Balanced scan
    THOROUGH = "thorough"  # Deep scan, all payloads, slower
    STEALTH = "stealth"  # Low-noise, evade WAF/IDS


class VulnScanner:
    """
    Enhanced unified vulnerability scanner.

    Features:
    - Multi-vulnerability type detection
    - Concurrent scanning with thread pooling
    - WAF detection and evasion
    - Recon pipeline integration
    - Multiple export formats
    - OWASP Top 10 mapping
    - Severity-based prioritization
    """

    # OWASP Top 10 2021 mapping
    OWASP_MAPPING = {
        "sqli": "A03:2021 - Injection",
        "xss": "A03:2021 - Injection",
        "ssrf": "A10:2021 - SSRF",
        "ssti": "A03:2021 - Injection",
        "xxe": "A05:2021 - Security Misconfiguration",
        "lfi": "A01:2021 - Broken Access Control",
        "jwt": "A07:2021 - Identification and Authentication Failures",
    }

    def __init__(self, callback_host: str = None, threads: int = 10,
                 mode: ScanMode = ScanMode.STANDARD):
        self.callback_host = callback_host
        self.threads = threads
        self.mode = mode

        # Initialize all scanners
        self.sqli = SQLiScanner()
        self.xss = XSSScanner()
        self.ssrf = SSRFScanner(callback_host)
        self.ssti = SSTIScanner(callback_host)
        self.xxe = XXEScanner(callback_host)
        self.lfi = LFIScanner(callback_host)
        self.jwt = JWTScanner(callback_host)

        self.findings = []
        self.waf_detected = False
        self.detected_technologies = []

        self.stats = {
            "endpoints_scanned": 0,
            "params_tested": 0,
            "vulns_found": 0,
            "by_type": {},
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "start_time": None,
            "end_time": None,
            "waf_detected": False,
        }
    
    def scan_endpoint(self, url: str, params: List[str] = None,
                      scan_types: List[str] = None,
                      detect_waf: bool = True) -> List[Dict]:
        """
        Scan single endpoint for multiple vulnerability types.

        Args:
            url: Target URL with query params
            params: Specific params to test (None = auto-detect)
            scan_types: List of vuln types or None for all
                       Options: sqli, xss, ssrf, ssti, xxe, lfi
            detect_waf: Enable WAF detection first

        Returns:
            List of vulnerability findings
        """
        findings = []

        if params is None:
            from urllib.parse import urlparse, parse_qs
            params = list(parse_qs(urlparse(url).query).keys())

        # Default scan types based on mode
        if scan_types is None:
            if self.mode == ScanMode.QUICK:
                scan_types = ["sqli", "xss"]
            elif self.mode == ScanMode.STEALTH:
                scan_types = ["sqli", "xss", "lfi"]
            else:
                scan_types = ["sqli", "xss", "ssrf", "ssti", "lfi"]

        # WAF detection
        if detect_waf:
            self._detect_waf(url)
            self.stats["waf_detected"] = self.waf_detected

        for param in params:
            self.stats["params_tested"] += 1

            # Classic web vulnerabilities
            if "sqli" in scan_types:
                sqli_findings = self.sqli.scan_param(url, param)
                self._enrich_findings(sqli_findings, "sqli")
                findings.extend(sqli_findings)

            if "xss" in scan_types:
                xss_findings = self.xss.scan_param(url, param)
                self._enrich_findings(xss_findings, "xss")
                findings.extend(xss_findings)

            if "ssrf" in scan_types:
                ssrf_findings = self.ssrf.scan_param(url, param)
                self._enrich_findings(ssrf_findings, "ssrf")
                findings.extend(ssrf_findings)

            # Advanced injection vulnerabilities
            if "ssti" in scan_types:
                ssti_findings = self.ssti.scan_param(url, param)
                self._enrich_findings(ssti_findings, "ssti")
                findings.extend(ssti_findings)

            if "lfi" in scan_types:
                lfi_findings = self.lfi.scan_param(url, param)
                self._enrich_findings(lfi_findings, "lfi")
                findings.extend(lfi_findings)

        # XXE requires special handling (POST with XML body)
        if "xxe" in scan_types:
            xxe_findings = self.xxe.scan_endpoint(url)
            self._enrich_findings(xxe_findings, "xxe")
            findings.extend(xxe_findings)

        self.stats["endpoints_scanned"] += 1
        return findings

    def scan_jwt(self, token: str) -> List[Dict]:
        """
        Scan a JWT token for vulnerabilities.

        Args:
            token: JWT token string

        Returns:
            List of JWT vulnerability findings
        """
        findings = self.jwt.scan_token(token)
        self._enrich_findings(findings, "jwt")
        return findings

    def _detect_waf(self, url: str) -> bool:
        """Detect if WAF is present."""
        import requests

        waf_test_payloads = [
            "' OR '1'='1",
            "<script>alert(1)</script>",
            "../../../etc/passwd",
        ]

        waf_signatures = [
            "cloudflare", "akamai", "imperva", "f5", "mod_security",
            "aws waf", "barracuda", "citrix", "fortiweb", "sucuri",
            "wordfence", "comodo", "incapsula", "radware"
        ]

        try:
            for payload in waf_test_payloads:
                resp = requests.get(
                    url, params={"test": payload},
                    timeout=5, verify=False
                )

                # Check response headers
                for header in ["Server", "X-Powered-By", "Via"]:
                    val = resp.headers.get(header, "").lower()
                    for sig in waf_signatures:
                        if sig in val:
                            self.waf_detected = True
                            return True

                # Check response body
                body_lower = resp.text.lower()
                if any(sig in body_lower for sig in waf_signatures):
                    self.waf_detected = True
                    return True

                # Check for blocked status codes
                if resp.status_code in [403, 406, 429, 503]:
                    self.waf_detected = True
                    return True

        except Exception:
            pass

        return False

    def _enrich_findings(self, findings: List[Dict], vuln_type: str):
        """Add metadata to findings."""
        for finding in findings:
            if "owasp" not in finding:
                finding["owasp"] = self.OWASP_MAPPING.get(vuln_type, "")
            if "waf_detected" not in finding:
                finding["waf_detected"] = self.waf_detected
            if "timestamp" not in finding:
                finding["timestamp"] = time.time()

            # Update stats
            severity = finding.get("severity", "MEDIUM")
            self.stats["by_severity"][severity] = \
                self.stats["by_severity"].get(severity, 0) + 1
            self.stats["by_type"][vuln_type] = \
                self.stats["by_type"].get(vuln_type, 0) + 1
    
    def scan_many(self, targets: List[Dict], scan_types: List[str] = None) -> List[Dict]:
        """Scan multiple targets concurrently.
        
        Args:
            targets: [{"url": "...", "params": ["id", "name"]}]
            scan_types: Vuln types to scan for
        
        Returns:
            Deduplicated findings list
        """
        self.stats["start_time"] = time.time()
        all_findings = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for target in targets:
                future = executor.submit(
                    self.scan_endpoint, 
                    target["url"], 
                    target.get("params"),
                    scan_types
                )
                futures[future] = target["url"]
            
            for future in as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    all_findings.extend(result)
                except Exception as e:
                    print(f"Error scanning {url}: {e}")
        
        self.stats["end_time"] = time.time()
        deduped = self._dedupe(all_findings)
        self.stats["vulns_found"] = len(deduped)
        self.findings = deduped
        
        return deduped
    
    def scan_from_recon(self, recon_output: Dict) -> List[Dict]:
        """Scan targets from recon pipeline output.
        
        Expected format:
        {
            "endpoints": [{"url": "...", "params": [...]}],
            "forms": [{"action": "...", "method": "...", "inputs": [...]}]
        }
        """
        targets = []
        
        # Process endpoints
        for ep in recon_output.get("endpoints", []):
            targets.append({
                "url": ep.get("url"),
                "params": ep.get("params", [])
            })
        
        # Process forms (convert to GET-style for scanning)
        for form in recon_output.get("forms", []):
            if form.get("inputs"):
                # Build URL with params
                from urllib.parse import urlencode
                base = form.get("action", "")
                params = {inp: "test" for inp in form.get("inputs", [])}
                url = f"{base}?{urlencode(params)}"
                targets.append({
                    "url": url,
                    "params": form.get("inputs", [])
                })
        
        return self.scan_many(targets)
    
    def _dedupe(self, findings: List[Dict]) -> List[Dict]:
        """Remove duplicate findings."""
        seen = set()
        unique = []
        
        for f in findings:
            key = (f["type"], f["url"], f["parameter"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        
        return unique
    
    def get_report(self) -> Dict:
        """Generate scan report."""
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        type_counts = {}
        
        for f in self.findings:
            sev = f.get("severity", "MEDIUM")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            vtype = f.get("type", "unknown")
            type_counts[vtype] = type_counts.get(vtype, 0) + 1
        
        duration = 0
        if self.stats["start_time"] and self.stats["end_time"]:
            duration = round(self.stats["end_time"] - self.stats["start_time"], 2)
        
        return {
            "summary": {
                "total_findings": len(self.findings),
                "endpoints_scanned": self.stats["endpoints_scanned"],
                "params_tested": self.stats["params_tested"],
                "duration_seconds": duration
            },
            "by_severity": severity_counts,
            "by_type": type_counts,
            "findings": self.findings
        }
    
    def export_findings(self, format: str = "json") -> str:
        """Export findings in various formats."""
        if format == "json":
            return json.dumps(self.get_report(), indent=2)
        elif format == "csv":
            lines = ["type,url,parameter,payload,severity,evidence"]
            for f in self.findings:
                lines.append(
                    f"{f.get('type','')},{f.get('url','')},{f.get('parameter','')},{f.get('payload','')},{f.get('severity','')},{f.get('evidence','')}"
                )
            return "\n".join(lines)
        elif format == "markdown":
            report = self.get_report()
            md = f"# Vulnerability Scan Report\n\n"
            md += f"## Summary\n- Total: {report['summary']['total_findings']}\n"
            md += f"- Endpoints: {report['summary']['endpoints_scanned']}\n"
            md += f"- Duration: {report['summary']['duration_seconds']}s\n\n"
            md += "## Findings by Severity\n"
            for sev, count in report["by_severity"].items():
                if count > 0:
                    md += f"- {sev}: {count}\n"
            md += "\n## Detailed Findings\n"
            for f in self.findings:
                md += f"\n### {f.get('type')} - {f.get('severity')}\n"
                md += f"- URL: `{f.get('url')}`\n"
                md += f"- Parameter: `{f.get('parameter')}`\n"
                md += f"- Payload: `{f.get('payload','N/A')}`\n"
                md += f"- Evidence: {f.get('evidence','N/A')}\n"
            return md
        else:
            return json.dumps(self.findings)


# Convenience functions
def quick_scan(url: str) -> List[Dict]:
    """Quick single-URL scan."""
    scanner = VulnScanner()
    return scanner.scan_endpoint(url)

def scan_urls(urls: List[str], threads: int = 10) -> List[Dict]:
    """Scan list of URLs."""
    scanner = VulnScanner(threads=threads)
    targets = [{"url": u} for u in urls]
    return scanner.scan_many(targets)
