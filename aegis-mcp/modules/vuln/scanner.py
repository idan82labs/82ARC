"""
Unified vulnerability scanner.
"""
from .sqli import SQLiScanner
from .xss import XSSScanner
from .ssrf import SSRFScanner
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import time

class VulnScanner:
    def __init__(self, callback_host: str = None, threads: int = 10):
        self.sqli = SQLiScanner()
        self.xss = XSSScanner()
        self.ssrf = SSRFScanner(callback_host)
        self.threads = threads
        self.findings = []
        self.stats = {
            "endpoints_scanned": 0,
            "params_tested": 0,
            "vulns_found": 0,
            "start_time": None,
            "end_time": None
        }
    
    def scan_endpoint(self, url: str, params: List[str] = None, 
                      scan_types: List[str] = None) -> List[Dict]:
        """Scan single endpoint.
        
        Args:
            url: Target URL with query params
            params: Specific params to test (None = all)
            scan_types: ["sqli", "xss", "ssrf"] or None for all
        """
        findings = []
        
        if params is None:
            from urllib.parse import urlparse, parse_qs
            params = list(parse_qs(urlparse(url).query).keys())
        
        if scan_types is None:
            scan_types = ["sqli", "xss", "ssrf"]
        
        for param in params:
            self.stats["params_tested"] += 1
            
            if "sqli" in scan_types:
                findings.extend(self.sqli.scan_param(url, param))
            if "xss" in scan_types:
                findings.extend(self.xss.scan_param(url, param))
            if "ssrf" in scan_types:
                findings.extend(self.ssrf.scan_param(url, param))
        
        self.stats["endpoints_scanned"] += 1
        return findings
    
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
