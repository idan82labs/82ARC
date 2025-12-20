"""
Content analysis for endpoint and parameter discovery.
Extracts attack surface from web content.
"""
import re
import requests
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from typing import Set, Dict, List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import base64

class ContentAnalyzer:
    def __init__(self):
        self.reset()
        
        # Sensitive patterns to flag
        self.sensitive_patterns = {
            "api_keys": [
                r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'["\']?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
                r'["\']?access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']',
            ],
            "aws_keys": [
                r'AKIA[0-9A-Z]{16}',
                r'["\']?aws[_-]?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+=]{40})["\']',
            ],
            "private_keys": [
                r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            ],
            "passwords": [
                r'["\']?password["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
                r'["\']?passwd["\']?\s*[:=]\s*["\']([^"\']{4,})["\']',
            ],
            "emails": [
                r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            ],
            "internal_ips": [
                r'(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}',
            ],
            "jwt_tokens": [
                r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            ],
            "urls_internal": [
                r'https?://(?:localhost|127\.0\.0\.1|internal|staging|dev)[^\s"\'<>]*',
            ],
        }
    
    def reset(self):
        """Reset state for new analysis."""
        self.endpoints = set()
        self.params = set()
        self.js_files = set()
        self.forms = []
        self.api_endpoints = set()
        self.comments = []
        self.secrets = []
        self.emails = set()
        self.subdomains = set()
        self.external_domains = set()
    
    def analyze(self, base_url: str, html: str) -> Dict:
        """Analyze page content for attack surface."""
        self.reset()
        base_domain = urlparse(base_url).netloc
        
        self._extract_links(base_url, html)
        self._extract_forms(base_url, html)
        self._extract_js(base_url, html)
        self._extract_api_patterns(html)
        self._extract_comments(html)
        self._find_secrets(html)
        self._extract_domains(base_domain, html)
        
        return {
            "base_url": base_url,
            "endpoints": sorted(list(self.endpoints)),
            "parameters": sorted(list(self.params)),
            "js_files": sorted(list(self.js_files)),
            "forms": self.forms,
            "api_endpoints": sorted(list(self.api_endpoints)),
            "comments": self.comments[:50],  # Limit
            "secrets_found": self.secrets,
            "emails": sorted(list(self.emails)),
            "subdomains": sorted(list(self.subdomains)),
            "external_domains": sorted(list(self.external_domains)),
            "stats": {
                "endpoints": len(self.endpoints),
                "parameters": len(self.params),
                "forms": len(self.forms),
                "secrets": len(self.secrets),
            }
        }
    
    def _extract_links(self, base: str, html: str):
        """Extract all links and their parameters."""
        base_domain = urlparse(base).netloc
        
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'data-url=["\']([^"\']+)["\']',
            r'data-href=["\']([^"\']+)["\']',
            r'url\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.I):
                url = match.group(1)
                
                # Skip data URIs, anchors, javascript
                if url.startswith(("data:", "javascript:", "mailto:", "#")):
                    continue
                
                # Make absolute
                if url.startswith("//"):
                    url = "https:" + url
                elif url.startswith("/") or not url.startswith("http"):
                    url = urljoin(base, url)
                
                parsed = urlparse(url)
                
                # Categorize
                if base_domain in parsed.netloc:
                    self.endpoints.add(url.split("?")[0].split("#")[0])
                    
                    # Extract parameters
                    for param in parse_qs(parsed.query).keys():
                        self.params.add(param)
                    
                    # Check if subdomain
                    if parsed.netloc != base_domain and base_domain in parsed.netloc:
                        self.subdomains.add(parsed.netloc)
                else:
                    self.external_domains.add(parsed.netloc)
    
    def _extract_forms(self, base: str, html: str):
        """Extract form details."""
        form_pattern = r'<form([^>]*)>(.*?)</form>'
        
        for match in re.finditer(form_pattern, html, re.I | re.S):
            attrs, content = match.groups()
            
            # Parse form attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', attrs, re.I)
            method_match = re.search(r'method=["\']([^"\']*)["\']', attrs, re.I)
            enctype_match = re.search(r'enctype=["\']([^"\']*)["\']', attrs, re.I)
            
            action = action_match.group(1) if action_match else ""
            method = method_match.group(1).upper() if method_match else "GET"
            enctype = enctype_match.group(1) if enctype_match else ""
            
            # Extract inputs
            inputs = []
            input_pattern = r'<(?:input|textarea|select)([^>]*)(?:>|/>)'
            for inp_match in re.finditer(input_pattern, content, re.I):
                inp_attrs = inp_match.group(1)
                
                name_match = re.search(r'name=["\']([^"\']+)["\']', inp_attrs, re.I)
                type_match = re.search(r'type=["\']([^"\']+)["\']', inp_attrs, re.I)
                
                if name_match:
                    name = name_match.group(1)
                    inp_type = type_match.group(1) if type_match else "text"
                    inputs.append({"name": name, "type": inp_type})
                    self.params.add(name)
            
            self.forms.append({
                "action": urljoin(base, action) if action else base,
                "method": method,
                "enctype": enctype,
                "inputs": inputs,
                "input_count": len(inputs)
            })
    
    def _extract_js(self, base: str, html: str):
        """Extract JavaScript files."""
        patterns = [
            r'src=["\']([^"\']*\.js[^"\']*)["\']',
            r'<script[^>]*src=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.I):
                js_url = match.group(1)
                if not js_url.startswith(("data:", "javascript:")):
                    self.js_files.add(urljoin(base, js_url))
    
    def _extract_api_patterns(self, html: str):
        """Find API endpoints in code."""
        api_patterns = [
            # REST patterns
            r'["\']/(api|v[0-9]+)/[^"\']+["\']',
            r'["\']https?://[^"\']*/(api|v[0-9]+)/[^"\']+["\']',
            
            # Fetch/XHR
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*`([^`]+)`',
            r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
            r'axios\.[a-z]+\s*\(\s*["\']([^"\']+)["\']',
            r'\$\.(?:ajax|get|post)\s*\(\s*["\']([^"\']+)["\']',
            r'\$\.(?:ajax|get|post)\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
            
            # GraphQL
            r'graphql|\/graphql',
            r'query\s*\{[^}]+\}',
            r'mutation\s*\{[^}]+\}',
            
            # WebSocket
            r'wss?://[^"\'<>\s]+',
        ]
        
        for pattern in api_patterns:
            for match in re.finditer(pattern, html, re.I):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                endpoint = endpoint.strip('"\'')
                if len(endpoint) > 3 and not endpoint.startswith("#"):
                    self.api_endpoints.add(endpoint)
    
    def _extract_comments(self, html: str):
        """Extract HTML and JS comments (often contain sensitive info)."""
        patterns = [
            r'<!--(.*?)-->',  # HTML comments
            r'/\*\*(.*?)\*/',  # JS block comments
            r'//\s*(TODO|FIXME|HACK|XXX|BUG|NOTE).*',  # Interesting inline
        ]
        
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.I | re.S):
                comment = match.group(1) if match.lastindex else match.group(0)
                comment = comment.strip()
                if len(comment) > 10 and len(comment) < 500:
                    self.comments.append(comment)
    
    def _find_secrets(self, html: str):
        """Find potential secrets and sensitive data."""
        for category, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                for match in re.finditer(pattern, html, re.I):
                    value = match.group(1) if match.lastindex else match.group(0)
                    
                    # Skip obvious false positives
                    if value.lower() in ["your_api_key", "example", "test", "xxx", "placeholder"]:
                        continue
                    
                    self.secrets.append({
                        "type": category,
                        "value": value[:100] + "..." if len(value) > 100 else value,
                        "context": html[max(0, match.start()-20):match.end()+20][:100]
                    })
                    
                    if category == "emails":
                        self.emails.add(value)
    
    def _extract_domains(self, base_domain: str, html: str):
        """Extract referenced domains."""
        domain_pattern = r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)'
        
        for match in re.finditer(domain_pattern, html):
            domain = match.group(1).lower()
            
            # Skip common CDNs and uninteresting
            skip = ["googleapis.com", "gstatic.com", "google.com", "facebook.com", 
                    "twitter.com", "cloudflare.com", "jquery.com", "jsdelivr.net",
                    "unpkg.com", "cdnjs.cloudflare.com", "w3.org"]
            if any(s in domain for s in skip):
                continue
            
            if base_domain in domain and domain != base_domain:
                self.subdomains.add(domain)
            elif base_domain not in domain:
                self.external_domains.add(domain)


class JSAnalyzer:
    """Dedicated JavaScript analysis for deeper endpoint discovery."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.endpoints = set()
        self.params = set()
        self.interesting = []
    
    def analyze_url(self, js_url: str) -> Dict:
        """Fetch and analyze a JS file."""
        try:
            resp = requests.get(js_url, timeout=self.timeout, verify=False)
            return self.analyze_content(resp.text, js_url)
        except:
            return {"url": js_url, "error": "Failed to fetch"}
    
    def analyze_content(self, js_content: str, source: str = "inline") -> Dict:
        """Analyze JS content for endpoints."""
        self.endpoints = set()
        self.params = set()
        self.interesting = []
        
        # Endpoint patterns
        endpoint_patterns = [
            r'["\']/((?:api|v[0-9]|admin|user|auth|login|logout|register|dashboard|account)[^"\']*)["\']',
            r'(?:path|url|endpoint|route)\s*[:=]\s*["\']([^"\']+)["\']',
            r'\.(?:get|post|put|patch|delete)\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in endpoint_patterns:
            for match in re.finditer(pattern, js_content, re.I):
                self.endpoints.add(match.group(1))
        
        # Parameter patterns
        param_patterns = [
            r'(?:params?|data|body|query)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)',
            r'(?:params?|data|body|query)\s*\[\s*["\']([^"\']+)["\']',
            r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']:\s*(?:true|false|null|\d|["\'])',
        ]
        
        for pattern in param_patterns:
            for match in re.finditer(pattern, js_content, re.I):
                self.params.add(match.group(1))
        
        # Find interesting strings
        interesting_patterns = [
            r'["\']([^"\']*(?:admin|password|secret|key|token|auth)[^"\']*)["\']',
        ]
        
        for pattern in interesting_patterns:
            for match in re.finditer(pattern, js_content, re.I):
                val = match.group(1)
                if len(val) > 3 and len(val) < 100:
                    self.interesting.append(val)
        
        return {
            "source": source,
            "endpoints": list(self.endpoints),
            "parameters": list(self.params),
            "interesting_strings": list(set(self.interesting))[:50]
        }


def analyze_page(url: str) -> Dict:
    """Quick analysis of a single page."""
    try:
        resp = requests.get(url, timeout=10, verify=False)
        analyzer = ContentAnalyzer()
        return analyzer.analyze(url, resp.text)
    except Exception as e:
        return {"url": url, "error": str(e)}


def analyze_js_files(js_urls: List[str]) -> List[Dict]:
    """Analyze multiple JS files."""
    analyzer = JSAnalyzer()
    results = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(analyzer.analyze_url, url): url for url in js_urls}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except:
                pass
    
    return results
