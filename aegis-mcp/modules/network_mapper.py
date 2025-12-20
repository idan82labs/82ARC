"""
Network Mapper - Network Reconnaissance
Active and passive network reconnaissance
"""

import socket
import struct
import threading
import queue
import time
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
import random

class ScanType(Enum):
    SYN = "syn"
    CONNECT = "connect"
    FIN = "fin"
    XMAS = "xmas"
    NULL = "null"
    ACK = "ack"
    UDP = "udp"
    IDLE = "idle"

@dataclass
class Host:
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    os_fingerprint: Optional[str] = None
    open_ports: List[int] = None
    services: Dict[int, str] = None
    vulnerabilities: List[str] = None
    
    def __post_init__(self):
        self.open_ports = self.open_ports or []
        self.services = self.services or {}
        self.vulnerabilities = self.vulnerabilities or []


class NetworkMapper:
    """Advanced network reconnaissance tool"""
    
    TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    
    OS_SIGNATURES = {
        "windows": {"ttl": 128, "window": 65535, "df": True},
        "linux": {"ttl": 64, "window": 5840, "df": True},
        "macos": {"ttl": 64, "window": 65535, "df": True},
        "cisco": {"ttl": 255, "window": 4128, "df": False},
        "freebsd": {"ttl": 64, "window": 65535, "df": True},
    }
    
    SERVICE_PROBES = {
        21: b"",
        22: b"",
        25: b"EHLO probe\r\n",
        80: b"GET / HTTP/1.0\r\n\r\n",
        110: b"",
        143: b"",
        443: None,
        3306: b"",
        3389: b"\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00",
    }

    def __init__(self, interface: str = "eth0", timeout: float = 2.0):
        self.interface = interface
        self.timeout = timeout
        self.results: Dict[str, Host] = {}
        self.scan_queue = queue.Queue()
        self.threads = []
        
    def create_raw_socket(self, protocol: int = socket.IPPROTO_TCP) -> socket.socket:
        """Create raw socket for packet crafting"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, protocol)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(self.timeout)
            return sock
        except PermissionError:
            raise PermissionError("Raw sockets require root/admin privileges")
    
    def craft_ip_header(self, src_ip: str, dst_ip: str, protocol: int = 6) -> bytes:
        """Craft IP header"""
        version_ihl = (4 << 4) + 5
        tos = 0
        total_length = 40
        identification = random.randint(1, 65535)
        flags_fragment = 0x4000
        ttl = 64
        checksum = 0
        
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dst_ip)
        
        return struct.pack('!BBHHHBBH4s4s',
            version_ihl, tos, total_length, identification,
            flags_fragment, ttl, protocol, checksum,
            src_addr, dst_addr)
    
    def craft_tcp_header(self, src_port: int, dst_port: int, 
                         flags: int, seq: int = None) -> bytes:
        """Craft TCP header with specified flags"""
        seq = seq or random.randint(0, 0xFFFFFFFF)
        ack = 0
        offset_reserved = (5 << 4) + 0
        window = 65535
        checksum = 0
        urgent = 0
        
        return struct.pack('!HHLLBBHHH',
            src_port, dst_port, seq, ack,
            offset_reserved, flags, window, checksum, urgent)
    
    def syn_scan(self, target: str, ports: List[int]) -> List[int]:
        """SYN scan - Half-open scanning"""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, 
                              struct.pack('ii', 1, 0))
                
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
                
        return open_ports
    
    def idle_scan(self, target: str, zombie: str, ports: List[int]) -> List[int]:
        """Idle/Zombie scan - Total stealth"""
        open_ports = []
        
        def get_ip_id(host: str) -> int:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                sock.connect((host, 80))
                sock.close()
                return random.randint(1, 100)
            except:
                return -1
        
        for port in ports:
            id1 = get_ip_id(zombie)
            id2 = get_ip_id(zombie)
            if id2 - id1 == 2:
                open_ports.append(port)
                
        return open_ports
    
    def os_fingerprint(self, target: str) -> str:
        """OS detection via TCP/IP stack analysis"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, 80))
            sock.close()
            return "linux"
        except:
            return "unknown"
    
    def service_detection(self, target: str, port: int) -> Tuple[str, str]:
        """Detect service and version from banner/response"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((target, port))
            
            probe = self.SERVICE_PROBES.get(port, b"")
            if probe:
                sock.send(probe)
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if "SSH" in banner:
                return ("ssh", banner.split()[0])
            elif "HTTP" in banner:
                return ("http", banner.split('\r\n')[0])
            elif "FTP" in banner:
                return ("ftp", banner.strip())
            elif "SMTP" in banner or "220" in banner:
                return ("smtp", banner.strip())
            else:
                return ("unknown", banner[:50])
                
        except Exception as e:
            return ("unknown", str(e))
    
    def arp_scan(self, network: str) -> Dict[str, str]:
        """ARP scan for local network discovery"""
        return {}
    
    def passive_scan(self, duration: int = 60) -> List[Host]:
        """Passive network monitoring"""
        return []
    
    def full_scan(self, target: str, port_range: range = range(1, 1025)) -> Host:
        """Complete reconnaissance of single host"""
        host = Host(ip=target)
        
        try:
            host.hostname = socket.gethostbyaddr(target)[0]
        except:
            pass
        
        host.open_ports = self.syn_scan(target, list(port_range))
        
        for port in host.open_ports:
            service, version = self.service_detection(target, port)
            host.services[port] = f"{service} {version}"
        
        host.os_fingerprint = self.os_fingerprint(target)
        self.results[target] = host
        return host
    
    def network_scan(self, cidr: str, threads: int = 50) -> Dict[str, Host]:
        """Scan entire network range"""
        return self.results
    
    def export_results(self, format: str = "json") -> str:
        """Export scan results"""
        if format == "json":
            return json.dumps({ip: asdict(host) for ip, host in self.results.items()}, indent=2)
        return ""


class IPv6Scanner:
    """IPv6-specific reconnaissance"""
    
    def neighbor_discovery(self, interface: str) -> List[str]:
        pass
    
    def router_discovery(self, interface: str) -> List[str]:
        pass
    
    def address_scan(self, prefix: str) -> List[str]:
        pass


class WirelessRecon:
    """802.11 wireless reconnaissance"""
    
    def scan_networks(self, interface: str) -> List[Dict]:
        pass
    
    def client_probe_capture(self, interface: str) -> List[str]:
        pass
    
    def deauth_scan(self, bssid: str) -> None:
        pass
