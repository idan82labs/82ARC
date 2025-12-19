"""
NIGHTOWL Vulnerability Scanner Module

Real vulnerability detection for:
- SQL Injection (error-based, time-based, boolean-based)
- Cross-Site Scripting (reflected, with context detection)
- Server-Side Request Forgery (internal access, cloud metadata, OOB)

Usage:
    from vuln import VulnScanner, quick_scan
    
    # Quick single URL
    findings = quick_scan("http://target.com/page?id=1")
    
    # Full scanner
    scanner = VulnScanner(callback_host="your.burp.collab")
    results = scanner.scan_many([
        {"url": "http://target.com/page?id=1", "params": ["id"]},
        {"url": "http://target.com/search?q=test", "params": ["q"]}
    ])
    
    # Generate report
    report = scanner.get_report()
    print(scanner.export_findings(format="markdown"))
"""

from .sqli import SQLiScanner
from .xss import XSSScanner
from .ssrf import SSRFScanner
from .scanner import VulnScanner, quick_scan, scan_urls

__all__ = [
    "SQLiScanner",
    "XSSScanner", 
    "SSRFScanner",
    "VulnScanner",
    "quick_scan",
    "scan_urls"
]
