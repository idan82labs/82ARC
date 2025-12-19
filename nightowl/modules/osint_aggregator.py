"""
OSINT Aggregator - Passive reconnaissance
Aggregates data from multiple sources without touching target
"""
import asyncio
import json
from dataclasses import dataclass
from typing import List, Dict, Optional
import re

try:
    import aiohttp
except ImportError:
    aiohttp = None

@dataclass
class Target:
    domain: str
    ips: List[str] = None
    subdomains: List[str] = None
    emails: List[str] = None
    employees: List[Dict] = None
    technologies: List[str] = None
    dns_records: Dict = None
    whois: Dict = None
    certificates: List[Dict] = None
    github_leaks: List[Dict] = None
    paste_leaks: List[Dict] = None
    
class OSINTAggregator:
    def __init__(self, api_keys: Dict[str, str] = None):
        self.api_keys = api_keys or {}
        self.session = None
        self.results = {}
        
    async def __aenter__(self):
        if aiohttp:
            self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
        
    async def enumerate_subdomains(self, domain: str) -> List[str]:
        """Passive subdomain enumeration via CT logs, DNS datasets"""
        subdomains = set()
        
        if not self.session:
            return list(subdomains)
        
        ct_url = f"https://crt.sh/?q=%.{domain}&output=json"
        try:
            async with self.session.get(ct_url) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        for sub in name.split('\n'):
                            if sub.endswith(domain):
                                subdomains.add(sub.lower())
        except:
            pass
        
        if 'securitytrails' in self.api_keys:
            st_url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": self.api_keys['securitytrails']}
            try:
                async with self.session.get(st_url, headers=headers) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data.get('subdomains', []):
                            subdomains.add(f"{sub}.{domain}")
            except:
                pass
        
        return list(subdomains)
    
    async def harvest_emails(self, domain: str) -> List[str]:
        """Email harvesting from public sources"""
        emails = set()
        
        if 'hunter' in self.api_keys and self.session:
            url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={self.api_keys['hunter']}"
            try:
                async with self.session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for email in data.get('data', {}).get('emails', []):
                            emails.add(email['value'])
            except:
                pass
        
        return list(emails)
    
    async def identify_technologies(self, domain: str) -> List[str]:
        """Technology stack identification"""
        techs = []
        
        if not self.session:
            return techs
        
        url = f"https://{domain}"
        try:
            async with self.session.get(url, timeout=10) as resp:
                headers = dict(resp.headers)
                body = await resp.text()
                
                if 'Server' in headers:
                    techs.append(f"Server: {headers['Server']}")
                
                if 'X-Powered-By' in headers:
                    techs.append(f"Framework: {headers['X-Powered-By']}")
                
                signatures = {
                    'WordPress': ['wp-content', 'wp-includes'],
                    'Drupal': ['Drupal', 'drupal.js'],
                    'React': ['react', '_reactRootContainer'],
                    'Angular': ['ng-app', 'angular'],
                    'Vue': ['vue.js', '__vue__'],
                    'ASP.NET': ['__VIEWSTATE', 'aspnet'],
                    'Cloudflare': ['cloudflare', 'cf-ray'],
                    'AWS': ['amazonaws', 'aws'],
                }
                
                for tech, sigs in signatures.items():
                    if any(sig.lower() in body.lower() or sig.lower() in str(headers).lower() for sig in sigs):
                        techs.append(tech)
                        
        except:
            pass
            
        return techs
    
    async def search_github_leaks(self, domain: str, org: str = None) -> List[Dict]:
        """Search GitHub for leaked credentials, API keys"""
        leaks = []
        
        if 'github' in self.api_keys and self.session:
            queries = [
                f'"{domain}" password',
                f'"{domain}" api_key',
                f'"{domain}" secret',
            ]
            
            headers = {"Authorization": f"token {self.api_keys['github']}"}
            
            for query in queries:
                try:
                    url = f"https://api.github.com/search/code?q={query}"
                    async with self.session.get(url, headers=headers) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            for item in data.get('items', [])[:10]:
                                leaks.append({
                                    'query': query,
                                    'repo': item['repository']['full_name'],
                                    'file': item['path'],
                                    'url': item['html_url']
                                })
                except:
                    pass
                            
        return leaks
    
    async def search_paste_sites(self, domain: str) -> List[Dict]:
        """Search paste sites for leaked data"""
        return []
    
    async def get_dns_records(self, domain: str) -> Dict:
        """Comprehensive DNS enumeration"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        
        if not self.session:
            return records
        
        for rtype in record_types:
            url = f"https://dns.google/resolve?name={domain}&type={rtype}"
            try:
                async with self.session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if 'Answer' in data:
                            records[rtype] = [a['data'] for a in data['Answer']]
            except:
                pass
                        
        return records
    
    async def full_recon(self, domain: str) -> Target:
        """Complete passive reconnaissance"""
        target = Target(domain=domain)
        
        results = await asyncio.gather(
            self.enumerate_subdomains(domain),
            self.harvest_emails(domain),
            self.identify_technologies(domain),
            self.get_dns_records(domain),
            self.search_github_leaks(domain),
            self.search_paste_sites(domain),
            return_exceptions=True
        )
        
        target.subdomains = results[0] if not isinstance(results[0], Exception) else []
        target.emails = results[1] if not isinstance(results[1], Exception) else []
        target.technologies = results[2] if not isinstance(results[2], Exception) else []
        target.dns_records = results[3] if not isinstance(results[3], Exception) else {}
        target.github_leaks = results[4] if not isinstance(results[4], Exception) else []
        target.paste_leaks = results[5] if not isinstance(results[5], Exception) else []
        
        return target


class CredentialHarvester:
    """Credential collection from various sources"""
    
    def __init__(self):
        self.credentials = []
        
    def parse_config_files(self, content: str, filename: str) -> List[Dict]:
        """Extract credentials from config files"""
        creds = []
        
        patterns = [
            (r'password\s*[=:]\s*["\']?([^"\'\s]+)', 'password'),
            (r'api[_-]?key\s*[=:]\s*["\']?([^"\'\s]+)', 'api_key'),
            (r'secret\s*[=:]\s*["\']?([^"\'\s]+)', 'secret'),
            (r'token\s*[=:]\s*["\']?([^"\'\s]+)', 'token'),
            (r'AKIA[0-9A-Z]{16}', 'aws_access_key'),
            (r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----', 'private_key'),
        ]
        
        for pattern, cred_type in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                creds.append({
                    'type': cred_type,
                    'value': match if isinstance(match, str) else match[0],
                    'source': filename
                })
                
        return creds


async def execute(target: str, mode: str = "full", api_keys: Dict = None) -> Dict:
    """Main execution entry point"""
    async with OSINTAggregator(api_keys) as recon:
        if mode == "full":
            result = await recon.full_recon(target)
            return result.__dict__
        elif mode == "subdomains":
            return {"subdomains": await recon.enumerate_subdomains(target)}
        elif mode == "emails":
            return {"emails": await recon.harvest_emails(target)}
        elif mode == "tech":
            return {"technologies": await recon.identify_technologies(target)}
        elif mode == "dns":
            return {"dns_records": await recon.get_dns_records(target)}
        elif mode == "leaks":
            github = await recon.search_github_leaks(target)
            paste = await recon.search_paste_sites(target)
            return {"github_leaks": github, "paste_leaks": paste}
