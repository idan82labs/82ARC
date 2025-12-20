"""
Real DNS enumeration using public APIs and DNS queries.
No external tools required - pure Python.
"""
import dns.resolver
import requests
import json
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import ssl
import re

class DNSEnumerator:
    def __init__(self, timeout: int = 10, threads: int = 30):
        self.timeout = timeout
        self.threads = threads
        self.results = {"subdomains": [], "records": {}}
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
    
    def crtsh_subdomains(self, domain: str) -> List[str]:
        """Query crt.sh for certificate transparency subdomains."""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subs.add(sub)
                return list(subs)
        except Exception as e:
            pass
        return []
    
    def hackertarget_subdomains(self, domain: str) -> List[str]:
        """Query HackerTarget for subdomains."""
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200 and "error" not in resp.text.lower():
                subs = set()
                for line in resp.text.strip().split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub.endswith(domain):
                            subs.add(sub)
                return list(subs)
        except:
            pass
        return []
    
    def threatcrowd_subdomains(self, domain: str) -> List[str]:
        """Query ThreatCrowd for subdomains."""
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        try:
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                subs = data.get("subdomains", [])
                return [s.lower() for s in subs if s.endswith(domain)]
        except:
            pass
        return []
    
    def dns_records(self, domain: str) -> Dict:
        """Get DNS records for domain."""
        records = {}
        rtypes = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV", "CAA"]
        
        for rtype in rtypes:
            try:
                answers = self.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, 
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            except Exception:
                pass
        
        return records
    
    def zone_transfer_attempt(self, domain: str) -> List[str]:
        """Attempt zone transfer (AXFR) on nameservers."""
        subs = []
        try:
            ns_records = self.resolver.resolve(domain, "NS")
            for ns in ns_records:
                ns_str = str(ns).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(
                        dns.query.xfr(ns_str, domain, timeout=self.timeout)
                    )
                    for name, node in zone.nodes.items():
                        sub = str(name)
                        if sub != "@":
                            subs.append(f"{sub}.{domain}")
                except:
                    pass
        except:
            pass
        return subs
    
    def resolve_subdomain(self, subdomain: str) -> Optional[Dict]:
        """Resolve single subdomain."""
        result = {"subdomain": subdomain, "ips": [], "cnames": []}
        
        try:
            # Try A records
            answers = self.resolver.resolve(subdomain, "A")
            result["ips"] = [str(r) for r in answers]
        except:
            pass
        
        try:
            # Try CNAME
            answers = self.resolver.resolve(subdomain, "CNAME")
            result["cnames"] = [str(r) for r in answers]
        except:
            pass
        
        if result["ips"] or result["cnames"]:
            return result
        return None
    
    def enumerate(self, domain: str, deep: bool = True) -> Dict:
        """Full enumeration combining multiple sources."""
        self.results = {
            "domain": domain,
            "subdomains": [],
            "records": {},
            "live_subdomains": [],
            "sources": {}
        }
        
        # Collect from multiple sources
        all_subs = set()
        
        # crt.sh (most reliable)
        crt_subs = self.crtsh_subdomains(domain)
        all_subs.update(crt_subs)
        self.results["sources"]["crtsh"] = len(crt_subs)
        
        if deep:
            # HackerTarget
            ht_subs = self.hackertarget_subdomains(domain)
            all_subs.update(ht_subs)
            self.results["sources"]["hackertarget"] = len(ht_subs)
            
            # Zone transfer attempt
            zt_subs = self.zone_transfer_attempt(domain)
            all_subs.update(zt_subs)
            self.results["sources"]["zone_transfer"] = len(zt_subs)
        
        self.results["subdomains"] = sorted(list(all_subs))
        
        # Get DNS records for main domain
        self.results["records"] = self.dns_records(domain)
        
        # Resolve subdomains concurrently
        live = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.resolve_subdomain, sub): sub 
                for sub in self.results["subdomains"][:500]  # Limit
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        live.append(result)
                except:
                    pass
        
        self.results["live_subdomains"] = live
        self.results["stats"] = {
            "total_found": len(self.results["subdomains"]),
            "live_resolved": len(live)
        }
        
        return self.results


def quick_enum(domain: str) -> Dict:
    """Quick enumeration function for direct use."""
    enum = DNSEnumerator()
    return enum.enumerate(domain, deep=False)


def deep_enum(domain: str) -> Dict:
    """Deep enumeration with all sources."""
    enum = DNSEnumerator()
    return enum.enumerate(domain, deep=True)
