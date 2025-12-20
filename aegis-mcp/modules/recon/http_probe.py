"""
HTTP probing for live hosts and technology fingerprinting.
Nation-state level capabilities with stealth options.
"""
import requests
import re
import hashlib
import ssl
import socket
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import warnings
import random
import time

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

class HTTPProber:
    def __init__(self, timeout: int = 10, threads: int = 30, 
                 stealth: bool = False, delay_range: Tuple[float, float] = (0, 0)):
        self.timeout = timeout
        self.threads = threads
        self.stealth = stealth
        self.delay_range = delay_range
        
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        ]
        
        self.tech_signatures = {
            # Web servers
            "nginx": [r"nginx", r"server:\s*nginx"],
            "apache": [r"apache", r"server:\s*apache"],
            "iis": [r"microsoft-iis", r"server:\s*microsoft"],
            "lighttpd": [r"server:\s*lighttpd"],
            "caddy": [r"server:\s*caddy"],
            "gunicorn": [r"server:\s*gunicorn"],
            "uvicorn": [r"server:\s*uvicorn"],
            
            # CDN/WAF
            "cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid"],
            "akamai": [r"akamai", r"x-akamai"],
            "fastly": [r"fastly", r"x-served-by.*cache"],
            "aws-cloudfront": [r"x-amz-cf", r"cloudfront"],
            "incapsula": [r"incapsula", r"incap_ses"],
            "sucuri": [r"sucuri", r"x-sucuri"],
            
            # Cloud providers
            "aws": [r"x-amz", r"amazonaws", r"aws-"],
            "azure": [r"azure", r"x-ms-", r"windows-azure"],
            "gcp": [r"x-goog", r"google-cloud", r"gcp"],
            "heroku": [r"heroku", r"x-heroku"],
            "vercel": [r"vercel", r"x-vercel"],
            "netlify": [r"netlify", r"x-nf-"],
            
            # CMS
            "wordpress": [r"wp-content", r"wp-includes", r"wp-json", r"/wp-admin"],
            "drupal": [r"drupal", r"/sites/default", r"x-drupal"],
            "joomla": [r"joomla", r"/administrator", r"com_content"],
            "magento": [r"magento", r"mage", r"/checkout/cart"],
            "shopify": [r"shopify", r"myshopify", r"cdn.shopify"],
            "squarespace": [r"squarespace", r"static.squarespace"],
            "wix": [r"wix", r"wixstatic", r"parastorage"],
            
            # Frameworks
            "react": [r"react", r"_reactroot", r"__react", r"reactdom"],
            "angular": [r"ng-version", r"ng-app", r"angular"],
            "vue": [r"vue", r"__vue__", r"v-app"],
            "next.js": [r"__next", r"next/static", r"_next"],
            "nuxt": [r"__nuxt", r"nuxt"],
            "django": [r"csrfmiddlewaretoken", r"django", r"__admin__"],
            "flask": [r"flask", r"werkzeug"],
            "laravel": [r"laravel_session", r"x-powered-by.*php", r"laravel"],
            "rails": [r"x-powered-by.*phusion", r"rails", r"_rails"],
            "spring": [r"spring", r"x-application-context"],
            "aspnet": [r"__viewstate", r"asp.net", r"x-aspnet", r".aspx"],
            "express": [r"x-powered-by.*express"],
            
            # Security headers (indicates security awareness)
            "csp-enabled": [r"content-security-policy"],
            "hsts-enabled": [r"strict-transport-security"],
            "xss-protection": [r"x-xss-protection"],
            
            # Authentication
            "oauth": [r"oauth", r"openid", r"authorization.*bearer"],
            "jwt": [r"jwt", r"json.?web.?token"],
            "saml": [r"saml", r"sso"],
            
            # APIs
            "graphql": [r"graphql", r"__schema", r"query.*mutation"],
            "rest-api": [r"/api/v[0-9]", r"application/json", r"x-api"],
            "swagger": [r"swagger", r"openapi", r"/api-docs"],
        }
        
        self.interesting_headers = [
            "server", "x-powered-by", "x-aspnet-version", "x-generator",
            "x-drupal-cache", "x-varnish", "x-cache", "via",
            "x-amz-cf-id", "cf-ray", "x-served-by", "x-backend-server",
            "x-request-id", "x-correlation-id", "x-trace-id",
            "content-security-policy", "strict-transport-security",
            "x-frame-options", "x-content-type-options",
            "access-control-allow-origin", "x-xss-protection"
        ]
    
    def _get_headers(self) -> Dict:
        """Generate request headers."""
        headers = {
            "User-Agent": random.choice(self.user_agents),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
        return headers
    
    def _extract_title(self, html: str) -> str:
        """Extract page title."""
        match = re.search(r"<title[^>]*>([^<]+)</title>", html, re.I)
        return match.group(1).strip()[:200] if match else ""
    
    def _fingerprint(self, resp) -> List[str]:
        """Fingerprint technologies from response."""
        techs = []
        content = resp.text.lower() + str(resp.headers).lower()
        
        for tech, patterns in self.tech_signatures.items():
            for pattern in patterns:
                if re.search(pattern, content, re.I):
                    techs.append(tech)
                    break
        
        return techs
    
    def _extract_interesting_headers(self, headers) -> Dict:
        """Extract security-relevant headers."""
        interesting = {}
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        for header in self.interesting_headers:
            if header in headers_lower:
                interesting[header] = headers_lower[header]
        
        return interesting
    
    def _get_ssl_info(self, hostname: str, port: int = 443) -> Optional[Dict]:
        """Get SSL certificate information."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        return {
                            "subject": dict(x[0] for x in cert.get("subject", [])),
                            "issuer": dict(x[0] for x in cert.get("issuer", [])),
                            "notBefore": cert.get("notBefore"),
                            "notAfter": cert.get("notAfter"),
                            "serialNumber": cert.get("serialNumber"),
                            "version": cert.get("version"),
                        }
        except:
            pass
        return None
    
    def probe_single(self, target: str) -> Dict:
        """Probe single target comprehensively."""
        if self.stealth and self.delay_range[1] > 0:
            time.sleep(random.uniform(*self.delay_range))
        
        # Normalize target
        if not target.startswith("http"):
            hostname = target
        else:
            hostname = urlparse(target).netloc
        
        result = {
            "target": target,
            "hostname": hostname,
            "live": False,
            "probes": []
        }
        
        # Try HTTPS first, then HTTP
        for scheme in ["https", "http"]:
            url = f"{scheme}://{hostname}"
            probe = {"scheme": scheme, "success": False}
            
            try:
                resp = requests.get(
                    url,
                    headers=self._get_headers(),
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False
                )
                
                probe["success"] = True
                probe["status"] = resp.status_code
                probe["final_url"] = resp.url
                probe["redirect_chain"] = [r.url for r in resp.history]
                probe["title"] = self._extract_title(resp.text)
                probe["content_length"] = len(resp.text)
                probe["content_hash"] = hashlib.sha256(resp.text.encode()).hexdigest()[:16]
                probe["headers_hash"] = hashlib.md5(
                    str(sorted(resp.headers.items())).encode()
                ).hexdigest()[:8]
                probe["interesting_headers"] = self._extract_interesting_headers(resp.headers)
                probe["technologies"] = self._fingerprint(resp)
                
                result["live"] = True
                result["primary"] = probe
                
                if scheme == "https":
                    probe["ssl"] = self._get_ssl_info(hostname)
                
                break  # Success, don't try HTTP
                
            except requests.exceptions.SSLError as e:
                probe["error"] = f"SSL: {str(e)[:100]}"
            except requests.exceptions.ConnectionError as e:
                probe["error"] = f"Connection: {str(e)[:100]}"
            except requests.exceptions.Timeout:
                probe["error"] = "Timeout"
            except Exception as e:
                probe["error"] = str(e)[:100]
            
            result["probes"].append(probe)
        
        return result
    
    def probe_many(self, targets: List[str], callback=None) -> List[Dict]:
        """Probe multiple targets concurrently."""
        results = []
        completed = 0
        total = len(targets)
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.probe_single, t): t for t in targets}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    if callback:
                        callback(completed, total, result)
                except Exception as e:
                    pass
        
        return results
    
    def get_live(self, results: List[Dict]) -> List[Dict]:
        """Filter to only live hosts."""
        return [r for r in results if r.get("live")]
    
    def summarize(self, results: List[Dict]) -> Dict:
        """Generate summary of probe results."""
        live = self.get_live(results)
        
        all_techs = []
        status_codes = {}
        
        for r in live:
            primary = r.get("primary", {})
            all_techs.extend(primary.get("technologies", []))
            
            status = primary.get("status")
            if status:
                status_codes[status] = status_codes.get(status, 0) + 1
        
        tech_counts = {}
        for t in all_techs:
            tech_counts[t] = tech_counts.get(t, 0) + 1
        
        return {
            "total_probed": len(results),
            "live_hosts": len(live),
            "status_codes": status_codes,
            "technologies": dict(sorted(tech_counts.items(), key=lambda x: -x[1])),
            "with_https": len([r for r in live if r.get("primary", {}).get("scheme") == "https"]),
        }


def quick_probe(targets: List[str]) -> List[Dict]:
    """Quick probe function for direct use."""
    prober = HTTPProber()
    return prober.get_live(prober.probe_many(targets))


def stealth_probe(targets: List[str], delay: float = 2.0) -> List[Dict]:
    """Stealth probe with delays."""
    prober = HTTPProber(stealth=True, delay_range=(delay/2, delay), threads=5)
    return prober.probe_many(targets)
