"""
Autonomous reconnaissance pipeline.
Combines all recon modules for full target mapping.
Nation-state level capabilities with operational flexibility.
"""
from typing import Dict, List, Optional, Callable
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import time
import hashlib
import requests
import warnings

warnings.filterwarnings("ignore")

# Import sibling modules
from .dns_enum import DNSEnumerator
from .http_probe import HTTPProber
from .content_analyzer import ContentAnalyzer, JSAnalyzer


class AutonomousRecon:
    """
    Full autonomous reconnaissance pipeline.
    Chains DNS enumeration → HTTP probing → Content analysis → JS analysis
    """
    
    def __init__(self, 
                 threads: int = 30,
                 timeout: int = 10,
                 stealth: bool = False,
                 delay: float = 0):
        """
        Initialize recon pipeline.
        
        Args:
            threads: Concurrent threads for scanning
            timeout: Request timeout in seconds
            stealth: Enable stealth mode (slower, less detectable)
            delay: Delay between requests in stealth mode
        """
        self.threads = threads
        self.timeout = timeout
        self.stealth = stealth
        self.delay = delay
        
        # Initialize modules
        self.dns = DNSEnumerator(timeout=timeout, threads=threads)
        self.http = HTTPProber(
            timeout=timeout, 
            threads=threads if not stealth else 5,
            stealth=stealth,
            delay_range=(delay/2, delay) if delay > 0 else (0, 0)
        )
        self.content = ContentAnalyzer()
        self.js_analyzer = JSAnalyzer(timeout=timeout)
        
        # State
        self.report = {}
        self.progress_callback = None
    
    def set_progress_callback(self, callback: Callable):
        """Set callback for progress updates: callback(phase, progress, message)"""
        self.progress_callback = callback
    
    def _progress(self, phase: str, progress: float, message: str):
        """Report progress."""
        if self.progress_callback:
            self.progress_callback(phase, progress, message)
        else:
            print(f"[{phase}] {progress:.0%} - {message}")
    
    def full_recon(self, domain: str, 
                   deep_dns: bool = True,
                   analyze_js: bool = True,
                   max_hosts: int = 100,
                   max_js: int = 50) -> Dict:
        """
        Complete autonomous reconnaissance.
        
        Args:
            domain: Target domain
            deep_dns: Use multiple DNS sources (slower but thorough)
            analyze_js: Analyze discovered JS files
            max_hosts: Maximum hosts to probe
            max_js: Maximum JS files to analyze
        
        Returns:
            Full reconnaissance report
        """
        start_time = time.time()
        
        self.report = {
            "target": domain,
            "timestamp": datetime.utcnow().isoformat(),
            "config": {
                "deep_dns": deep_dns,
                "analyze_js": analyze_js,
                "stealth": self.stealth,
                "threads": self.threads
            },
            "phases": {},
            "attack_surface": {},
            "summary": {}
        }
        
        # Phase 1: DNS Enumeration
        self._progress("dns", 0, f"Starting DNS enumeration for {domain}")
        dns_results = self.dns.enumerate(domain, deep=deep_dns)
        self.report["phases"]["dns"] = {
            "subdomains_found": len(dns_results.get("subdomains", [])),
            "live_resolved": len(dns_results.get("live_subdomains", [])),
            "records": dns_results.get("records", {}),
            "sources": dns_results.get("sources", {})
        }
        self._progress("dns", 1.0, f"Found {len(dns_results.get('subdomains', []))} subdomains")
        
        # Build target list for HTTP probing
        targets = [domain]
        for sub in dns_results.get("live_subdomains", [])[:max_hosts-1]:
            targets.append(sub["subdomain"])
        targets = list(set(targets))
        
        # Phase 2: HTTP Probing
        self._progress("http", 0, f"Probing {len(targets)} targets")
        http_results = self.http.probe_many(targets)
        live_hosts = self.http.get_live(http_results)
        
        self.report["phases"]["http"] = {
            "targets_probed": len(targets),
            "live_hosts": len(live_hosts),
            "summary": self.http.summarize(http_results)
        }
        self._progress("http", 1.0, f"{len(live_hosts)} live hosts found")
        
        # Phase 3: Content Analysis
        self._progress("content", 0, "Analyzing page content")
        all_endpoints = set()
        all_params = set()
        all_js = set()
        all_forms = []
        all_apis = set()
        all_secrets = []
        all_techs = set()
        
        analyzed = 0
        for host in live_hosts:
            primary = host.get("primary", {})
            final_url = primary.get("final_url", f"https://{host['hostname']}")
            
            try:
                resp = requests.get(final_url, timeout=self.timeout, verify=False)
                analysis = self.content.analyze(final_url, resp.text)
                
                all_endpoints.update(analysis.get("endpoints", []))
                all_params.update(analysis.get("parameters", []))
                all_js.update(analysis.get("js_files", []))
                all_forms.extend(analysis.get("forms", []))
                all_apis.update(analysis.get("api_endpoints", []))
                all_secrets.extend(analysis.get("secrets_found", []))
                all_techs.update(primary.get("technologies", []))
                
            except Exception as e:
                pass
            
            analyzed += 1
            self._progress("content", analyzed / len(live_hosts), 
                          f"Analyzed {analyzed}/{len(live_hosts)} hosts")
        
        self.report["phases"]["content"] = {
            "hosts_analyzed": analyzed,
            "endpoints_found": len(all_endpoints),
            "parameters_found": len(all_params),
            "forms_found": len(all_forms),
            "js_files_found": len(all_js),
            "api_endpoints_found": len(all_apis),
            "secrets_found": len(all_secrets)
        }
        
        # Phase 4: JS Analysis (optional)
        js_insights = []
        if analyze_js and all_js:
            self._progress("js", 0, f"Analyzing {min(len(all_js), max_js)} JS files")
            js_to_analyze = list(all_js)[:max_js]
            
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(self.js_analyzer.analyze_url, url): url 
                          for url in js_to_analyze}
                
                done = 0
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if "endpoints" in result:
                            all_endpoints.update(result.get("endpoints", []))
                            all_params.update(result.get("parameters", []))
                            if result.get("interesting_strings"):
                                js_insights.append(result)
                    except:
                        pass
                    done += 1
                    self._progress("js", done / len(js_to_analyze), 
                                  f"Analyzed {done}/{len(js_to_analyze)} JS files")
            
            self.report["phases"]["js"] = {
                "files_analyzed": len(js_to_analyze),
                "additional_endpoints": len(all_endpoints) - self.report["phases"]["content"]["endpoints_found"],
                "interesting_files": len(js_insights)
            }
        
        # Build attack surface
        self.report["attack_surface"] = {
            "live_hosts": [
                {
                    "hostname": h["hostname"],
                    "url": h.get("primary", {}).get("final_url"),
                    "technologies": h.get("primary", {}).get("technologies", []),
                    "title": h.get("primary", {}).get("title", ""),
                    "status": h.get("primary", {}).get("status")
                }
                for h in live_hosts
            ],
            "endpoints": sorted(list(all_endpoints))[:500],  # Limit output
            "parameters": sorted(list(all_params)),
            "forms": all_forms[:100],
            "api_endpoints": sorted(list(all_apis)),
            "secrets": all_secrets,
            "technologies": sorted(list(all_techs))
        }
        
        # Generate summary
        elapsed = time.time() - start_time
        self.report["summary"] = {
            "duration_seconds": round(elapsed, 2),
            "subdomains_discovered": len(dns_results.get("subdomains", [])),
            "live_hosts": len(live_hosts),
            "total_endpoints": len(all_endpoints),
            "total_parameters": len(all_params),
            "total_forms": len(all_forms),
            "api_endpoints": len(all_apis),
            "secrets_exposed": len(all_secrets),
            "technologies": sorted(list(all_techs)),
            "attack_vectors": self._identify_attack_vectors(all_forms, all_apis, all_secrets, all_techs)
        }
        
        self._progress("complete", 1.0, 
                      f"Recon complete: {len(live_hosts)} hosts, {len(all_endpoints)} endpoints")
        
        return self.report
    
    def _identify_attack_vectors(self, forms: List, apis: set, secrets: List, techs: set) -> List[str]:
        """Identify potential attack vectors from gathered intelligence."""
        vectors = []
        
        # Form-based vectors
        if forms:
            has_login = any("login" in str(f).lower() or "password" in str(f).lower() for f in forms)
            has_upload = any(f.get("enctype") == "multipart/form-data" for f in forms)
            has_search = any("search" in str(f).lower() or "query" in str(f).lower() for f in forms)
            
            if has_login:
                vectors.append("authentication_forms")
            if has_upload:
                vectors.append("file_upload")
            if has_search:
                vectors.append("search_injection")
        
        # API vectors
        if apis:
            vectors.append("api_endpoints")
            if any("graphql" in str(a).lower() for a in apis):
                vectors.append("graphql_introspection")
        
        # Secret exposure
        if secrets:
            vectors.append("credential_exposure")
        
        # Technology-specific
        tech_lower = [t.lower() for t in techs]
        if "wordpress" in tech_lower:
            vectors.append("wordpress_vulns")
        if "drupal" in tech_lower:
            vectors.append("drupal_vulns")
        if any(t in tech_lower for t in ["angular", "react", "vue"]):
            vectors.append("spa_vulnerabilities")
        if "aws" in tech_lower or "s3" in str(techs).lower():
            vectors.append("aws_misconfiguration")
        
        return vectors
    
    def quick_recon(self, domain: str) -> Dict:
        """Quick reconnaissance - DNS + HTTP only, no deep analysis."""
        return self.full_recon(domain, deep_dns=False, analyze_js=False, max_hosts=50)
    
    def stealth_recon(self, domain: str) -> Dict:
        """Stealth reconnaissance - slower, less detectable."""
        self.stealth = True
        self.delay = 2.0
        self.http = HTTPProber(
            timeout=self.timeout,
            threads=5,
            stealth=True,
            delay_range=(1, 3)
        )
        return self.full_recon(domain, deep_dns=True, analyze_js=True, max_hosts=30, max_js=20)
    
    def export_json(self, filepath: str = None) -> str:
        """Export report as JSON."""
        output = json.dumps(self.report, indent=2)
        if filepath:
            with open(filepath, "w") as f:
                f.write(output)
        return output
    
    def export_targets(self) -> Dict[str, List[str]]:
        """Export discovered targets in formats for other tools."""
        attack_surface = self.report.get("attack_surface", {})
        
        return {
            "hosts": [h["hostname"] for h in attack_surface.get("live_hosts", [])],
            "urls": [h["url"] for h in attack_surface.get("live_hosts", []) if h.get("url")],
            "endpoints": attack_surface.get("endpoints", []),
            "parameters": attack_surface.get("parameters", []),
            "api_endpoints": attack_surface.get("api_endpoints", [])
        }


# Convenience functions
def quick_enum(domain: str) -> Dict:
    """Quick autonomous recon."""
    recon = AutonomousRecon()
    return recon.quick_recon(domain)


def full_enum(domain: str) -> Dict:
    """Full autonomous recon with all features."""
    recon = AutonomousRecon()
    return recon.full_recon(domain)


def stealth_enum(domain: str) -> Dict:
    """Stealth recon with delays and reduced concurrency."""
    recon = AutonomousRecon(stealth=True, delay=2.0, threads=5)
    return recon.stealth_recon(domain)
