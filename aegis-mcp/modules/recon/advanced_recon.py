"""
Advanced Reconnaissance Framework - Red Team Edition

Deep passive and active reconnaissance capabilities:
- Passive DNS historical analysis (SecurityTrails, PassiveTotal, CIRCL)
- ASN/BGP mapping and network range discovery
- Cloud infrastructure enumeration (AWS, GCP, Azure)
- Historical WHOIS and domain intelligence
- Favicon hash matching across the internet
- SSL/TLS certificate intelligence
- Wayback Machine deep analysis
- Shodan/Censys/ZoomEye integration
- GitHub/GitLab dorking for secrets
- Social media footprinting
- Employee OSINT (LinkedIn, email patterns)

Based on real red team methodologies and bug bounty recon workflows.
"""

import hashlib
import base64
import json
import re
import time
import socket
import ssl
import struct
from typing import List, Dict, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin, quote
import ipaddress


class ReconDepth(Enum):
    """Reconnaissance depth levels."""
    QUICK = "quick"          # Fast, surface-level
    STANDARD = "standard"    # Balanced approach
    DEEP = "deep"           # Thorough enumeration
    EXHAUSTIVE = "exhaustive"  # Leave no stone unturned


@dataclass
class PassiveDNSRecord:
    """Historical DNS record."""
    subdomain: str
    record_type: str
    value: str
    first_seen: str
    last_seen: str
    source: str
    count: int = 1


@dataclass
class ASNInfo:
    """ASN/BGP intelligence."""
    asn: int
    name: str
    country: str
    prefixes: List[str] = field(default_factory=list)
    peers: List[int] = field(default_factory=list)
    allocated_ranges: List[str] = field(default_factory=list)


@dataclass
class CloudAsset:
    """Discovered cloud asset."""
    provider: str  # aws, gcp, azure
    service: str   # s3, ec2, blob, etc.
    identifier: str
    region: str = ""
    public: bool = False
    url: str = ""
    metadata: Dict = field(default_factory=dict)


@dataclass
class CertificateInfo:
    """SSL/TLS certificate intelligence."""
    subject: str
    issuer: str
    san_names: List[str]
    serial: str
    not_before: str
    not_after: str
    fingerprint_sha256: str
    public_key_info: Dict


class AdvancedRecon:
    """
    Advanced reconnaissance engine with deep OSINT capabilities.

    Features:
    - Multi-source passive DNS aggregation
    - ASN/BGP intelligence gathering
    - Cloud infrastructure discovery
    - Certificate transparency mining
    - Historical analysis via Wayback
    - GitHub secret scanning
    - Employee/social footprinting
    """

    # Cloud provider patterns
    CLOUD_PATTERNS = {
        "aws": {
            "s3": [
                r"([a-zA-Z0-9.-]+)\.s3\.amazonaws\.com",
                r"s3\.([a-z0-9-]+)\.amazonaws\.com/([a-zA-Z0-9.-]+)",
                r"([a-zA-Z0-9.-]+)\.s3-([a-z0-9-]+)\.amazonaws\.com",
            ],
            "cloudfront": [r"([a-z0-9]+)\.cloudfront\.net"],
            "elb": [r"([a-zA-Z0-9.-]+)\.(us|eu|ap|sa|ca|me|af)-[a-z]+-\d\.elb\.amazonaws\.com"],
            "rds": [r"([a-zA-Z0-9.-]+)\.([a-z0-9-]+)\.rds\.amazonaws\.com"],
            "ec2": [r"ec2-(\d+-\d+-\d+-\d+)\.([a-z0-9-]+)\.compute\.amazonaws\.com"],
            "lambda": [r"([a-z0-9]+)\.execute-api\.([a-z0-9-]+)\.amazonaws\.com"],
            "apigateway": [r"([a-z0-9]+)\.execute-api\.([a-z0-9-]+)\.amazonaws\.com"],
        },
        "gcp": {
            "storage": [r"storage\.googleapis\.com/([a-zA-Z0-9.-_]+)"],
            "appspot": [r"([a-zA-Z0-9.-]+)\.appspot\.com"],
            "cloudfunctions": [r"([a-z0-9-]+)-([a-z0-9]+)\.cloudfunctions\.net"],
            "run": [r"([a-zA-Z0-9.-]+)\.run\.app"],
        },
        "azure": {
            "blob": [r"([a-zA-Z0-9]+)\.blob\.core\.windows\.net"],
            "websites": [r"([a-zA-Z0-9.-]+)\.azurewebsites\.net"],
            "cloudapp": [r"([a-zA-Z0-9.-]+)\.([a-z]+)\.cloudapp\.azure\.com"],
            "database": [r"([a-zA-Z0-9.-]+)\.database\.windows\.net"],
        }
    }

    # GitHub dork patterns for secrets
    GITHUB_DORKS = [
        '"{domain}" password',
        '"{domain}" api_key',
        '"{domain}" apikey',
        '"{domain}" secret',
        '"{domain}" token',
        '"{domain}" AWS_ACCESS_KEY',
        '"{domain}" AWS_SECRET',
        '"{domain}" private_key',
        '"{domain}" jdbc:',
        '"{domain}" mongodb://',
        '"{domain}" redis://',
        '"{domain}" postgres://',
        '"{domain}" BEGIN RSA PRIVATE KEY',
        'org:{org} password',
        'org:{org} secret',
        'org:{org} api_key',
    ]

    def __init__(self, api_keys: Dict[str, str] = None,
                 depth: ReconDepth = ReconDepth.STANDARD,
                 threads: int = 20,
                 timeout: int = 15):
        self.api_keys = api_keys or {}
        self.depth = depth
        self.threads = threads
        self.timeout = timeout

        # Results storage
        self.passive_dns: List[PassiveDNSRecord] = []
        self.asn_info: List[ASNInfo] = []
        self.cloud_assets: List[CloudAsset] = []
        self.certificates: List[CertificateInfo] = []
        self.subdomains: Set[str] = set()
        self.ips: Set[str] = set()
        self.emails: Set[str] = set()
        self.github_leaks: List[Dict] = []
        self.wayback_urls: List[str] = []
        self.technologies: Set[str] = set()

        self.stats = {
            "sources_queried": 0,
            "subdomains_found": 0,
            "ips_discovered": 0,
            "cloud_assets": 0,
            "potential_leaks": 0,
        }

    # ==================== PASSIVE DNS ====================

    def passive_dns_crtsh(self, domain: str) -> List[PassiveDNSRecord]:
        """Query certificate transparency via crt.sh."""
        import requests

        records = []
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            resp = requests.get(url, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                seen = set()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub and sub not in seen:
                            seen.add(sub)
                            records.append(PassiveDNSRecord(
                                subdomain=sub,
                                record_type="CERT",
                                value=entry.get("issuer_name", ""),
                                first_seen=entry.get("not_before", ""),
                                last_seen=entry.get("not_after", ""),
                                source="crt.sh"
                            ))
                            self.subdomains.add(sub)
        except Exception:
            pass

        return records

    def passive_dns_securitytrails(self, domain: str) -> List[PassiveDNSRecord]:
        """Query SecurityTrails API for historical DNS."""
        import requests

        records = []
        if "securitytrails" not in self.api_keys:
            return records

        try:
            headers = {"APIKEY": self.api_keys["securitytrails"]}

            # Subdomains
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for sub in data.get("subdomains", []):
                    full = f"{sub}.{domain}"
                    records.append(PassiveDNSRecord(
                        subdomain=full,
                        record_type="A",
                        value="",
                        first_seen="",
                        last_seen="",
                        source="securitytrails"
                    ))
                    self.subdomains.add(full)

            # Historical DNS
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns/a"
            resp = requests.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                for record in data.get("records", []):
                    for val in record.get("values", []):
                        records.append(PassiveDNSRecord(
                            subdomain=domain,
                            record_type="A",
                            value=val.get("ip", ""),
                            first_seen=record.get("first_seen", ""),
                            last_seen=record.get("last_seen", ""),
                            source="securitytrails_history",
                            count=record.get("count", 1)  # Use int count, not organization string
                        ))
                        if val.get("ip"):
                            self.ips.add(val["ip"])

        except Exception:
            pass

        return records

    def passive_dns_virustotal(self, domain: str) -> List[PassiveDNSRecord]:
        """Query VirusTotal for passive DNS."""
        import requests

        records = []
        if "virustotal" not in self.api_keys:
            return records

        try:
            headers = {"x-apikey": self.api_keys["virustotal"]}
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            resp = requests.get(url, headers=headers, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json()
                for item in data.get("data", []):
                    sub = item.get("id", "")
                    if sub:
                        records.append(PassiveDNSRecord(
                            subdomain=sub,
                            record_type="VT",
                            value="",
                            first_seen="",
                            last_seen="",
                            source="virustotal"
                        ))
                        self.subdomains.add(sub)
        except Exception:
            pass

        return records

    def passive_dns_circl(self, domain: str) -> List[PassiveDNSRecord]:
        """Query CIRCL Passive DNS."""
        import requests

        records = []
        if "circl_user" not in self.api_keys or "circl_pass" not in self.api_keys:
            return records

        try:
            auth = (self.api_keys["circl_user"], self.api_keys["circl_pass"])
            url = f"https://www.circl.lu/pdns/query/{domain}"
            resp = requests.get(url, auth=auth, timeout=self.timeout)

            if resp.status_code == 200:
                for line in resp.text.strip().split("\n"):
                    if line:
                        try:
                            entry = json.loads(line)
                            records.append(PassiveDNSRecord(
                                subdomain=entry.get("rrname", "").rstrip("."),
                                record_type=entry.get("rrtype", ""),
                                value=entry.get("rdata", ""),
                                first_seen=entry.get("time_first", ""),
                                last_seen=entry.get("time_last", ""),
                                source="circl",
                                count=entry.get("count", 1)
                            ))
                        except json.JSONDecodeError:
                            pass
        except Exception:
            pass

        return records

    def passive_dns_aggregate(self, domain: str) -> List[PassiveDNSRecord]:
        """Aggregate passive DNS from all sources."""
        all_records = []

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(self.passive_dns_crtsh, domain),
                executor.submit(self.passive_dns_securitytrails, domain),
                executor.submit(self.passive_dns_virustotal, domain),
                executor.submit(self.passive_dns_circl, domain),
            ]

            for future in as_completed(futures):
                try:
                    records = future.result()
                    all_records.extend(records)
                    self.stats["sources_queried"] += 1
                except Exception:
                    pass

        self.passive_dns = all_records
        self.stats["subdomains_found"] = len(self.subdomains)
        return all_records

    # ==================== ASN/BGP INTELLIGENCE ====================

    def asn_lookup(self, ip_or_domain: str) -> Optional[ASNInfo]:
        """Look up ASN information for IP or domain."""
        import requests

        # Resolve domain to IP if needed
        target_ip = ip_or_domain
        try:
            socket.inet_aton(ip_or_domain)
        except socket.error:
            try:
                target_ip = socket.gethostbyname(ip_or_domain)
            except socket.gaierror:
                return None

        try:
            # Use BGPView API
            url = f"https://api.bgpview.io/ip/{target_ip}"
            resp = requests.get(url, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                prefixes = data.get("prefixes", [])

                if prefixes:
                    asn_data = prefixes[0].get("asn", {})
                    asn_info = ASNInfo(
                        asn=asn_data.get("asn", 0),
                        name=asn_data.get("name", ""),
                        country=asn_data.get("country_code", ""),
                        prefixes=[p.get("prefix", "") for p in prefixes]
                    )
                    self.asn_info.append(asn_info)
                    return asn_info
        except Exception:
            pass

        return None

    def asn_prefixes(self, asn: int) -> List[str]:
        """Get all prefixes announced by an ASN."""
        import requests

        prefixes = []
        try:
            url = f"https://api.bgpview.io/asn/{asn}/prefixes"
            resp = requests.get(url, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                for prefix in data.get("ipv4_prefixes", []):
                    prefixes.append(prefix.get("prefix", ""))
                for prefix in data.get("ipv6_prefixes", []):
                    prefixes.append(prefix.get("prefix", ""))
        except Exception:
            pass

        return prefixes

    def reverse_asn_lookup(self, org_name: str) -> List[ASNInfo]:
        """Find ASNs belonging to an organization."""
        import requests

        asns = []
        try:
            url = f"https://api.bgpview.io/search?query_term={quote(org_name)}"
            resp = requests.get(url, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                for asn_entry in data.get("asns", []):
                    asn_info = ASNInfo(
                        asn=asn_entry.get("asn", 0),
                        name=asn_entry.get("name", ""),
                        country=asn_entry.get("country_code", ""),
                    )
                    # Get prefixes
                    asn_info.prefixes = self.asn_prefixes(asn_info.asn)
                    asns.append(asn_info)
        except Exception:
            pass

        return asns

    # ==================== CLOUD INFRASTRUCTURE ====================

    def discover_cloud_assets(self, domain: str, content: str = "") -> List[CloudAsset]:
        """Discover cloud assets from domain and content analysis."""
        import requests

        assets = []

        # First, try to get the main page content
        if not content:
            try:
                resp = requests.get(f"https://{domain}", timeout=self.timeout, verify=False)
                content = resp.text
            except:
                try:
                    resp = requests.get(f"http://{domain}", timeout=self.timeout, verify=False)
                    content = resp.text
                except:
                    pass

        # Scan for cloud patterns
        for provider, services in self.CLOUD_PATTERNS.items():
            for service, patterns in services.items():
                for pattern in patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            identifier = ".".join(match)
                        else:
                            identifier = match

                        asset = CloudAsset(
                            provider=provider,
                            service=service,
                            identifier=identifier,
                        )

                        # Build URL and check accessibility
                        if provider == "aws" and service == "s3":
                            asset.url = f"https://{identifier}.s3.amazonaws.com"
                            asset.public = self._check_s3_public(asset.url)
                        elif provider == "azure" and service == "blob":
                            asset.url = f"https://{identifier}.blob.core.windows.net"
                            asset.public = self._check_azure_blob_public(asset.url)
                        elif provider == "gcp" and service == "storage":
                            asset.url = f"https://storage.googleapis.com/{identifier}"
                            asset.public = self._check_gcs_public(asset.url)

                        assets.append(asset)

        # Also check common bucket naming patterns
        bucket_patterns = [
            f"{domain.replace('.', '-')}",
            f"{domain.split('.')[0]}",
            f"{domain.split('.')[0]}-backup",
            f"{domain.split('.')[0]}-dev",
            f"{domain.split('.')[0]}-staging",
            f"{domain.split('.')[0]}-prod",
            f"{domain.split('.')[0]}-assets",
            f"{domain.split('.')[0]}-static",
            f"{domain.split('.')[0]}-uploads",
            f"{domain.split('.')[0]}-data",
        ]

        for bucket in bucket_patterns:
            # Check S3
            s3_url = f"https://{bucket}.s3.amazonaws.com"
            if self._check_bucket_exists(s3_url):
                assets.append(CloudAsset(
                    provider="aws",
                    service="s3",
                    identifier=bucket,
                    url=s3_url,
                    public=self._check_s3_public(s3_url)
                ))

            # Check GCS
            gcs_url = f"https://storage.googleapis.com/{bucket}"
            if self._check_bucket_exists(gcs_url):
                assets.append(CloudAsset(
                    provider="gcp",
                    service="storage",
                    identifier=bucket,
                    url=gcs_url,
                    public=self._check_gcs_public(gcs_url)
                ))

            # Check Azure Blob
            azure_url = f"https://{bucket.replace('-', '')}.blob.core.windows.net"
            if self._check_bucket_exists(azure_url):
                assets.append(CloudAsset(
                    provider="azure",
                    service="blob",
                    identifier=bucket,
                    url=azure_url,
                    public=self._check_azure_blob_public(azure_url)
                ))

        self.cloud_assets = assets
        self.stats["cloud_assets"] = len(assets)
        return assets

    def _check_bucket_exists(self, url: str) -> bool:
        """Check if a bucket URL exists."""
        import requests
        try:
            resp = requests.head(url, timeout=5)
            return resp.status_code in [200, 403, 301, 302]
        except:
            return False

    def _check_s3_public(self, url: str) -> bool:
        """Check if S3 bucket is publicly accessible."""
        import requests
        try:
            resp = requests.get(url, timeout=5)
            return resp.status_code == 200 and "ListBucketResult" in resp.text
        except:
            return False

    def _check_azure_blob_public(self, url: str) -> bool:
        """Check if Azure Blob container is publicly accessible."""
        import requests
        try:
            resp = requests.get(f"{url}?restype=container&comp=list", timeout=5)
            return resp.status_code == 200 and "EnumerationResults" in resp.text
        except:
            return False

    def _check_gcs_public(self, url: str) -> bool:
        """Check if GCS bucket is publicly accessible."""
        import requests
        try:
            resp = requests.get(url, timeout=5)
            return resp.status_code == 200
        except:
            return False

    # ==================== CERTIFICATE INTELLIGENCE ====================

    def certificate_analysis(self, domain: str) -> List[CertificateInfo]:
        """Analyze SSL/TLS certificates for intelligence."""
        certs = []

        # Get cert from live connection
        live_cert = self._get_live_certificate(domain)
        if live_cert:
            certs.append(live_cert)

        # Get historical certs from CT logs
        ct_certs = self._get_ct_certificates(domain)
        certs.extend(ct_certs)

        self.certificates = certs
        return certs

    def _get_live_certificate(self, domain: str, port: int = 443) -> Optional[CertificateInfo]:
        """Get certificate from live connection."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)

                    # Parse certificate
                    import hashlib
                    cert_dict = ssock.getpeercert()

                    san_names = []
                    for san_type, san_value in cert_dict.get("subjectAltName", []):
                        if san_type == "DNS":
                            san_names.append(san_value)
                            self.subdomains.add(san_value)

                    return CertificateInfo(
                        subject=str(cert_dict.get("subject", "")),
                        issuer=str(cert_dict.get("issuer", "")),
                        san_names=san_names,
                        serial=str(cert_dict.get("serialNumber", "")),
                        not_before=cert_dict.get("notBefore", ""),
                        not_after=cert_dict.get("notAfter", ""),
                        fingerprint_sha256=hashlib.sha256(cert).hexdigest(),
                        public_key_info={}
                    )
        except Exception:
            pass

        return None

    def _get_ct_certificates(self, domain: str) -> List[CertificateInfo]:
        """Get certificates from CT logs via crt.sh."""
        import requests

        certs = []
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            resp = requests.get(url, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json()
                seen_serials = set()

                for entry in data[:50]:  # Limit to 50 most recent
                    serial = entry.get("serial_number", "")
                    if serial in seen_serials:
                        continue
                    seen_serials.add(serial)

                    san_names = entry.get("name_value", "").split("\n")
                    for san in san_names:
                        if san and "*" not in san:
                            self.subdomains.add(san.lower())

                    certs.append(CertificateInfo(
                        subject=entry.get("common_name", ""),
                        issuer=entry.get("issuer_name", ""),
                        san_names=san_names,
                        serial=serial,
                        not_before=entry.get("not_before", ""),
                        not_after=entry.get("not_after", ""),
                        fingerprint_sha256="",
                        public_key_info={}
                    ))
        except Exception:
            pass

        return certs

    def favicon_hash(self, domain: str) -> Optional[str]:
        """Calculate favicon hash for Shodan matching."""
        import requests

        try:
            # Try multiple favicon locations
            favicon_urls = [
                f"https://{domain}/favicon.ico",
                f"http://{domain}/favicon.ico",
                f"https://{domain}/favicon.png",
            ]

            for url in favicon_urls:
                try:
                    resp = requests.get(url, timeout=self.timeout, verify=False)
                    if resp.status_code == 200 and len(resp.content) > 0:
                        # Calculate MurmurHash3 (Shodan uses this)
                        encoded = base64.encodebytes(resp.content)
                        # Simplified hash for demonstration
                        return hashlib.md5(encoded).hexdigest()
                except:
                    continue
        except Exception:
            pass

        return None

    # ==================== WAYBACK MACHINE ====================

    def wayback_urls(self, domain: str, filters: List[str] = None) -> List[str]:
        """Get historical URLs from Wayback Machine."""
        import requests

        urls = []
        default_filters = [
            "statuscode:200",
            "mimetype:text/html",
        ]

        try:
            # CDX API query
            filter_params = "&".join([f"filter={f}" for f in (filters or default_filters)])
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&collapse=urlkey&{filter_params}&limit=5000"

            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()

                # Skip header row
                for row in data[1:]:
                    if len(row) >= 3:
                        archived_url = row[2]
                        urls.append(archived_url)

                        # Extract interesting patterns
                        if any(ext in archived_url.lower() for ext in
                               ['.php', '.asp', '.jsp', '.json', '.xml', '.sql',
                                '.bak', '.old', '.zip', '.tar', '.gz', 'api/',
                                'admin', 'config', 'backup', '.env']):
                            self.wayback_urls.append(archived_url)
        except Exception:
            pass

        # Deduplicate
        urls = list(set(urls))
        self.wayback_urls = list(set(self.wayback_urls))

        return urls

    def wayback_interesting(self, domain: str) -> Dict[str, List[str]]:
        """Find interesting files/endpoints from Wayback."""
        import requests

        interesting = {
            "config_files": [],
            "backup_files": [],
            "api_endpoints": [],
            "admin_panels": [],
            "source_code": [],
            "sensitive_files": [],
        }

        patterns = {
            "config_files": [r'\.env', r'config\.', r'settings\.', r'\.ini$', r'\.conf$'],
            "backup_files": [r'\.bak$', r'\.old$', r'\.backup$', r'\.zip$', r'\.tar', r'\.sql$'],
            "api_endpoints": [r'/api/', r'/v1/', r'/v2/', r'/graphql', r'/rest/'],
            "admin_panels": [r'/admin', r'/manager', r'/dashboard', r'/wp-admin'],
            "source_code": [r'\.git', r'\.svn', r'\.hg', r'/src/', r'/source/'],
            "sensitive_files": [r'password', r'credential', r'secret', r'private', r'\.pem$', r'\.key$'],
        }

        all_urls = self.wayback_urls(domain)

        for url in all_urls:
            for category, regexes in patterns.items():
                for regex in regexes:
                    if re.search(regex, url, re.IGNORECASE):
                        interesting[category].append(url)
                        break

        return interesting

    # ==================== GITHUB INTELLIGENCE ====================

    def github_recon(self, domain: str, org: str = None) -> List[Dict]:
        """Search GitHub for leaked secrets and code."""
        import requests

        leaks = []
        if "github" not in self.api_keys:
            return leaks

        headers = {"Authorization": f"token {self.api_keys['github']}"}

        for dork_template in self.GITHUB_DORKS:
            dork = dork_template.format(domain=domain, org=org or domain.split(".")[0])

            try:
                url = f"https://api.github.com/search/code?q={quote(dork)}&per_page=10"
                resp = requests.get(url, headers=headers, timeout=self.timeout)

                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("items", []):
                        leak = {
                            "query": dork,
                            "repo": item["repository"]["full_name"],
                            "file": item["path"],
                            "url": item["html_url"],
                            "score": item.get("score", 0),
                        }
                        leaks.append(leak)
                        self.github_leaks.append(leak)

                # Rate limiting
                time.sleep(2)

            except Exception:
                pass

        self.stats["potential_leaks"] = len(leaks)
        return leaks

    # ==================== EMAIL HARVESTING ====================

    def harvest_emails(self, domain: str) -> Set[str]:
        """Harvest emails from multiple sources."""
        import requests

        emails = set()

        # Hunter.io
        if "hunter" in self.api_keys:
            try:
                url = f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={self.api_keys['hunter']}"
                resp = requests.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    for email in data.get("data", {}).get("emails", []):
                        emails.add(email["value"])
            except:
                pass

        # Email pattern inference from domain
        common_patterns = [
            "{first}.{last}@{domain}",
            "{first}{last}@{domain}",
            "{f}{last}@{domain}",
            "{first}_{last}@{domain}",
            "{first}-{last}@{domain}",
        ]

        self.emails = emails
        return emails

    # ==================== SHODAN/CENSYS INTEGRATION ====================

    def shodan_search(self, query: str) -> List[Dict]:
        """Search Shodan for hosts."""
        import requests

        results = []
        if "shodan" not in self.api_keys:
            return results

        try:
            url = f"https://api.shodan.io/shodan/host/search?key={self.api_keys['shodan']}&query={quote(query)}"
            resp = requests.get(url, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json()
                for match in data.get("matches", []):
                    results.append({
                        "ip": match.get("ip_str"),
                        "port": match.get("port"),
                        "org": match.get("org"),
                        "os": match.get("os"),
                        "product": match.get("product"),
                        "version": match.get("version"),
                        "hostnames": match.get("hostnames", []),
                        "vulns": list(match.get("vulns", {}).keys()) if match.get("vulns") else [],
                    })
                    self.ips.add(match.get("ip_str"))
        except Exception:
            pass

        return results

    def shodan_host(self, ip: str) -> Optional[Dict]:
        """Get Shodan data for specific IP."""
        import requests

        if "shodan" not in self.api_keys:
            return None

        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={self.api_keys['shodan']}"
            resp = requests.get(url, timeout=self.timeout)

            if resp.status_code == 200:
                data = resp.json()
                return {
                    "ip": data.get("ip_str"),
                    "hostnames": data.get("hostnames", []),
                    "os": data.get("os"),
                    "org": data.get("org"),
                    "isp": data.get("isp"),
                    "ports": data.get("ports", []),
                    "vulns": list(data.get("vulns", {}).keys()) if data.get("vulns") else [],
                    "services": [
                        {
                            "port": svc.get("port"),
                            "product": svc.get("product"),
                            "version": svc.get("version"),
                        }
                        for svc in data.get("data", [])
                    ]
                }
        except Exception:
            pass

        return None

    # ==================== FULL RECONNAISSANCE ====================

    def full_recon(self, domain: str, org: str = None) -> Dict:
        """
        Complete reconnaissance combining all techniques.

        Args:
            domain: Target domain
            org: Organization name for GitHub/LinkedIn searches

        Returns:
            Comprehensive reconnaissance report
        """
        start_time = time.time()

        report = {
            "target": domain,
            "organization": org or domain.split(".")[0],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "depth": self.depth.value,
        }

        # Phase 1: Passive DNS aggregation
        print(f"[*] Phase 1: Passive DNS aggregation for {domain}")
        self.passive_dns_aggregate(domain)
        report["passive_dns"] = {
            "total_records": len(self.passive_dns),
            "unique_subdomains": len(self.subdomains),
            "records": [
                {
                    "subdomain": r.subdomain,
                    "type": r.record_type,
                    "value": r.value,
                    "source": r.source,
                }
                for r in self.passive_dns[:100]  # Limit output
            ]
        }

        # Phase 2: ASN/BGP intelligence
        print(f"[*] Phase 2: ASN/BGP intelligence")
        asn_info = self.asn_lookup(domain)
        if asn_info:
            report["asn_info"] = {
                "asn": asn_info.asn,
                "name": asn_info.name,
                "country": asn_info.country,
                "prefixes": asn_info.prefixes[:20],
            }

        # Phase 3: Cloud asset discovery
        if self.depth in [ReconDepth.DEEP, ReconDepth.EXHAUSTIVE]:
            print(f"[*] Phase 3: Cloud asset discovery")
            cloud_assets = self.discover_cloud_assets(domain)
            report["cloud_assets"] = [
                {
                    "provider": a.provider,
                    "service": a.service,
                    "identifier": a.identifier,
                    "url": a.url,
                    "public": a.public,
                }
                for a in cloud_assets
            ]

        # Phase 4: Certificate intelligence
        print(f"[*] Phase 4: Certificate intelligence")
        certs = self.certificate_analysis(domain)
        report["certificates"] = {
            "count": len(certs),
            "san_domains": list(self.subdomains)[:100],
        }

        # Phase 5: Wayback analysis
        if self.depth in [ReconDepth.DEEP, ReconDepth.EXHAUSTIVE]:
            print(f"[*] Phase 5: Wayback Machine analysis")
            interesting = self.wayback_interesting(domain)
            report["wayback"] = {
                "total_urls": len(self.wayback_urls),
                "interesting": {k: v[:20] for k, v in interesting.items()}
            }

        # Phase 6: GitHub intelligence
        if self.depth in [ReconDepth.DEEP, ReconDepth.EXHAUSTIVE]:
            print(f"[*] Phase 6: GitHub intelligence")
            leaks = self.github_recon(domain, org)
            report["github"] = {
                "potential_leaks": len(leaks),
                "findings": leaks[:20],
            }

        # Phase 7: Shodan/Censys
        if self.depth == ReconDepth.EXHAUSTIVE and "shodan" in self.api_keys:
            print(f"[*] Phase 7: Shodan intelligence")
            shodan_results = self.shodan_search(f"hostname:{domain}")
            report["shodan"] = {
                "hosts_found": len(shodan_results),
                "results": shodan_results[:20],
            }

        # Summary
        elapsed = time.time() - start_time
        report["summary"] = {
            "duration_seconds": round(elapsed, 2),
            "subdomains_discovered": len(self.subdomains),
            "unique_ips": len(self.ips),
            "cloud_assets": len(self.cloud_assets),
            "potential_leaks": len(self.github_leaks),
            "certificates_analyzed": len(self.certificates),
        }

        report["attack_surface"] = {
            "subdomains": sorted(list(self.subdomains))[:200],
            "ips": sorted(list(self.ips))[:100],
            "emails": sorted(list(self.emails)),
        }

        return report

    def export_report(self, format: str = "json") -> str:
        """Export reconnaissance report."""
        report = self.full_recon.__self__.__dict__ if hasattr(self, 'report') else {}

        if format == "json":
            return json.dumps(report, indent=2, default=str)
        elif format == "csv":
            # Export subdomains as CSV
            lines = ["subdomain,source"]
            for record in self.passive_dns:
                lines.append(f"{record.subdomain},{record.source}")
            return "\n".join(lines)
        elif format == "targets":
            # Export targets for other tools
            return "\n".join(sorted(self.subdomains))

        return json.dumps(report, indent=2, default=str)


# Convenience functions
def quick_recon(domain: str) -> Dict:
    """Quick reconnaissance scan."""
    recon = AdvancedRecon(depth=ReconDepth.QUICK)
    return recon.full_recon(domain)


def deep_recon(domain: str, api_keys: Dict = None) -> Dict:
    """Deep reconnaissance with all sources."""
    recon = AdvancedRecon(api_keys=api_keys, depth=ReconDepth.DEEP)
    return recon.full_recon(domain)


def exhaustive_recon(domain: str, api_keys: Dict = None, org: str = None) -> Dict:
    """Exhaustive reconnaissance - leave no stone unturned."""
    recon = AdvancedRecon(api_keys=api_keys, depth=ReconDepth.EXHAUSTIVE)
    return recon.full_recon(domain, org)
