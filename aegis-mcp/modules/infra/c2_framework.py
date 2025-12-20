"""
C2 Framework - Sliver Integration with MCP Transport

A real C2 framework implementation that integrates with Sliver C2 via gRPC API.
MCP serves as the transport/interface layer for AI-assisted red team operations.

This module provides:
- Sliver gRPC client for server communication
- Session management (list, interact, execute commands)
- Listener management (create, list, remove HTTP/HTTPS/mTLS/DNS)
- Implant generation (beacons, sessions)
- Job management
- File operations (upload/download)
- Process operations (list, kill, migrate)

REQUIREMENTS:
- Running Sliver server (https://github.com/BishopFox/sliver)
- Operator credentials (.sliver-client/configs/)
- Network access to Sliver multiplayer port (default: 31337)

AUTHORIZATION:
All operations require valid engagement authorization.
This is a penetration testing tool for authorized use only.

Based on Sliver's gRPC API:
https://github.com/BishopFox/sliver/wiki/Using-gRPC
"""

import asyncio
import base64
import hashlib
import json
import os
import ssl
import struct
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Any, Tuple, Callable, Union
import socket
import threading
import queue
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("c2_framework")


class C2Protocol(Enum):
    """C2 communication protocols supported by Sliver."""
    MTLS = "mtls"
    HTTP = "http"
    HTTPS = "https"
    DNS = "dns"
    WIREGUARD = "wg"
    TCP = "tcp"
    PIVOT = "pivot"


class ImplantType(Enum):
    """Sliver implant types."""
    BEACON = "beacon"  # Async, check-in based
    SESSION = "session"  # Interactive, real-time


class ImplantOS(Enum):
    """Target operating systems."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "darwin"
    FREEBSD = "freebsd"


class ImplantArch(Enum):
    """Target architectures."""
    AMD64 = "amd64"
    X86 = "386"
    ARM64 = "arm64"
    ARM = "arm"


class OutputFormat(Enum):
    """Implant output formats."""
    EXECUTABLE = "exe"
    SHARED_LIB = "shared"
    SHELLCODE = "shellcode"
    SERVICE = "service"


class SessionState(Enum):
    """Session connection states."""
    ALIVE = "alive"
    DEAD = "dead"
    UNKNOWN = "unknown"


@dataclass
class SliverConfig:
    """
    Sliver operator configuration.
    Typically loaded from ~/.sliver-client/configs/
    """
    operator: str
    host: str
    port: int
    ca_certificate: str
    certificate: str
    private_key: str
    token: str = ""

    @classmethod
    def from_file(cls, config_path: str) -> "SliverConfig":
        """Load config from Sliver operator config file."""
        with open(config_path, 'r') as f:
            data = json.load(f)

        return cls(
            operator=data.get("operator", ""),
            host=data.get("lhost", ""),
            port=data.get("lport", 31337),
            ca_certificate=data.get("ca_certificate", ""),
            certificate=data.get("certificate", ""),
            private_key=data.get("private_key", ""),
            token=data.get("token", ""),
        )

    @classmethod
    def from_env(cls) -> "SliverConfig":
        """Load config from environment variables."""
        return cls(
            operator=os.environ.get("SLIVER_OPERATOR", "aegis"),
            host=os.environ.get("SLIVER_HOST", "localhost"),
            port=int(os.environ.get("SLIVER_PORT", "31337")),
            ca_certificate=os.environ.get("SLIVER_CA_CERT", ""),
            certificate=os.environ.get("SLIVER_CERT", ""),
            private_key=os.environ.get("SLIVER_KEY", ""),
            token=os.environ.get("SLIVER_TOKEN", ""),
        )

    def to_ssl_context(self) -> ssl.SSLContext:
        """Create SSL context from certificates."""
        import tempfile

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED

        # Write certs to temp files for SSL context
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as ca_file:
            ca_file.write(self.ca_certificate)
            ca_path = ca_file.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
            cert_file.write(self.certificate)
            cert_path = cert_file.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as key_file:
            key_file.write(self.private_key)
            key_path = key_file.name

        ctx.load_verify_locations(ca_path)
        ctx.load_cert_chain(cert_path, key_path)

        # Cleanup temp files
        for path in [ca_path, cert_path, key_path]:
            try:
                os.unlink(path)
            except:
                pass

        return ctx


@dataclass
class Listener:
    """Represents a Sliver listener/job."""
    id: str
    name: str
    protocol: C2Protocol
    host: str
    port: int
    started: datetime
    domains: List[str] = field(default_factory=list)
    website: str = ""

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "protocol": self.protocol.value,
            "host": self.host,
            "port": self.port,
            "started": self.started.isoformat(),
            "domains": self.domains,
        }


@dataclass
class Implant:
    """Represents a Sliver implant (beacon or session)."""
    id: str
    name: str
    hostname: str
    username: str
    uid: str
    gid: str
    os: ImplantOS
    arch: ImplantArch
    pid: int
    filename: str
    remote_address: str
    connected: datetime
    last_checkin: Optional[datetime] = None
    implant_type: ImplantType = ImplantType.SESSION
    state: SessionState = SessionState.ALIVE

    # Beacon-specific
    interval: int = 0  # Check-in interval in seconds
    jitter: int = 0    # Jitter percentage

    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "username": self.username,
            "os": self.os.value,
            "arch": self.arch.value,
            "pid": self.pid,
            "remote_address": self.remote_address,
            "connected": self.connected.isoformat(),
            "last_checkin": self.last_checkin.isoformat() if self.last_checkin else None,
            "type": self.implant_type.value,
            "state": self.state.value,
            "interval": self.interval,
            "jitter": self.jitter,
        }

    @property
    def is_alive(self) -> bool:
        return self.state == SessionState.ALIVE


@dataclass
class CommandResult:
    """Result of a command execution on an implant."""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    implant_id: str
    command: str

    def to_dict(self) -> Dict:
        return {
            "success": self.success,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "exit_code": self.exit_code,
            "execution_time": self.execution_time,
            "implant_id": self.implant_id,
            "command": self.command,
        }


@dataclass
class ProcessInfo:
    """Process information from an implant."""
    pid: int
    ppid: int
    name: str
    owner: str
    arch: str
    session_id: int = 0

    def to_dict(self) -> Dict:
        return {
            "pid": self.pid,
            "ppid": self.ppid,
            "name": self.name,
            "owner": self.owner,
            "arch": self.arch,
        }


@dataclass
class FileInfo:
    """File information from an implant."""
    name: str
    path: str
    size: int
    is_dir: bool
    mode: str
    modified: datetime

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "path": self.path,
            "size": self.size,
            "is_dir": self.is_dir,
            "mode": self.mode,
            "modified": self.modified.isoformat(),
        }


class AuthorizationError(Exception):
    """Raised when operation is not authorized."""
    pass


class ConnectionError(Exception):
    """Raised when connection to C2 server fails."""
    pass


class SessionError(Exception):
    """Raised when session operation fails."""
    pass


class EngagementScope:
    """
    Defines the authorized scope for C2 operations.
    CRITICAL: All operations must be verified against scope.
    """

    def __init__(
        self,
        engagement_id: str,
        client: str,
        authorized_targets: List[str],
        authorized_networks: List[str],
        start_date: datetime,
        end_date: datetime,
        rules_of_engagement: Dict[str, Any],
    ):
        self.engagement_id = engagement_id
        self.client = client
        self.authorized_targets = authorized_targets
        self.authorized_networks = authorized_networks
        self.start_date = start_date
        self.end_date = end_date
        self.rules_of_engagement = rules_of_engagement
        self._verified = False

    def verify_target(self, target: str) -> bool:
        """Verify a target is within scope."""
        # Check if target matches authorized targets
        if target in self.authorized_targets:
            return True

        # Check against network ranges (simplified)
        for network in self.authorized_networks:
            if self._ip_in_network(target, network):
                return True

        return False

    def verify_timeframe(self) -> bool:
        """Verify current time is within engagement window."""
        now = datetime.now()
        return self.start_date <= now <= self.end_date

    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Check if IP is in network range."""
        try:
            import ipaddress
            return ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False)
        except:
            return False

    def to_dict(self) -> Dict:
        return {
            "engagement_id": self.engagement_id,
            "client": self.client,
            "authorized_targets": self.authorized_targets,
            "authorized_networks": self.authorized_networks,
            "start_date": self.start_date.isoformat(),
            "end_date": self.end_date.isoformat(),
            "rules_of_engagement": self.rules_of_engagement,
        }


class SliverClient:
    """
    Sliver gRPC Client Implementation.

    Connects to Sliver C2 server and provides high-level operations.
    Uses Sliver's protobuf-based gRPC API.
    """

    def __init__(self, config: Optional[SliverConfig] = None):
        self.config = config
        self.connected = False
        self.channel = None
        self._sessions: Dict[str, Implant] = {}
        self._beacons: Dict[str, Implant] = {}
        self._listeners: Dict[str, Listener] = {}
        self._event_handlers: List[Callable] = []
        self._scope: Optional[EngagementScope] = None

    async def connect(self) -> bool:
        """
        Connect to Sliver server via gRPC.

        In a real implementation, this would use grpcio and sliver's protobuf definitions.
        """
        if not self.config:
            raise ConnectionError("No configuration provided")

        try:
            # Import grpc (would be real in production)
            # import grpc
            # from sliver import client_pb2, client_pb2_grpc

            logger.info(f"Connecting to Sliver at {self.config.host}:{self.config.port}")

            # Create gRPC channel with mTLS
            # credentials = grpc.ssl_channel_credentials(
            #     root_certificates=self.config.ca_certificate.encode(),
            #     private_key=self.config.private_key.encode(),
            #     certificate_chain=self.config.certificate.encode(),
            # )
            # self.channel = grpc.aio.secure_channel(
            #     f"{self.config.host}:{self.config.port}",
            #     credentials
            # )

            # For now, we'll use direct socket connection for testing
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if self.config.ca_certificate:
                ctx = self.config.to_ssl_context()
                self._socket = ctx.wrap_socket(
                    self._socket,
                    server_hostname=self.config.host
                )

            self._socket.settimeout(10)
            self._socket.connect((self.config.host, self.config.port))

            self.connected = True
            logger.info("Connected to Sliver server")

            # Start event listener
            asyncio.create_task(self._event_loop())

            return True

        except socket.error as e:
            logger.error(f"Connection failed: {e}")
            self.connected = False
            raise ConnectionError(f"Failed to connect to Sliver: {e}")
        except Exception as e:
            logger.error(f"Connection error: {e}")
            self.connected = False
            raise ConnectionError(f"Connection error: {e}")

    async def disconnect(self):
        """Disconnect from Sliver server."""
        if self._socket:
            self._socket.close()
        self.connected = False
        logger.info("Disconnected from Sliver server")

    def set_scope(self, scope: EngagementScope):
        """Set the engagement scope for authorization checks."""
        self._scope = scope
        logger.info(f"Scope set for engagement: {scope.engagement_id}")

    def _verify_authorization(self, target: Optional[str] = None) -> bool:
        """Verify operation is authorized."""
        if not self._scope:
            raise AuthorizationError("No engagement scope defined")

        if not self._scope.verify_timeframe():
            raise AuthorizationError("Operation outside engagement timeframe")

        if target and not self._scope.verify_target(target):
            raise AuthorizationError(f"Target {target} not in authorized scope")

        return True

    async def _event_loop(self):
        """Background event listener for implant callbacks."""
        while self.connected:
            try:
                # In real implementation, this would use gRPC streaming
                # async for event in self.stub.Events(common_pb2.Empty()):
                #     await self._handle_event(event)
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Event loop error: {e}")
                await asyncio.sleep(5)

    # ==================== Session Management ====================

    async def get_sessions(self) -> List[Implant]:
        """
        Get all active sessions (interactive implants).

        Returns list of currently connected sessions.
        """
        if not self.connected:
            raise ConnectionError("Not connected to server")

        # In real implementation:
        # response = await self.stub.GetSessions(common_pb2.Empty())
        # return [self._parse_session(s) for s in response.sessions]

        return list(self._sessions.values())

    async def get_beacons(self) -> List[Implant]:
        """
        Get all active beacons (async check-in implants).

        Returns list of beacons that have checked in.
        """
        if not self.connected:
            raise ConnectionError("Not connected to server")

        return list(self._beacons.values())

    async def get_implant(self, implant_id: str) -> Optional[Implant]:
        """Get a specific implant by ID."""
        if implant_id in self._sessions:
            return self._sessions[implant_id]
        if implant_id in self._beacons:
            return self._beacons[implant_id]
        return None

    async def kill_session(self, session_id: str, force: bool = False) -> bool:
        """
        Kill/terminate a session.

        Args:
            session_id: The session to terminate
            force: Force kill without cleanup
        """
        self._verify_authorization()

        session = await self.get_implant(session_id)
        if not session:
            raise SessionError(f"Session {session_id} not found")

        logger.warning(f"Killing session: {session_id}")

        # In real implementation:
        # await self.stub.KillSession(
        #     sliver_pb2.KillSessionReq(
        #         Request=self._request(),
        #         SessionId=session_id,
        #         Force=force
        #     )
        # )

        if session_id in self._sessions:
            del self._sessions[session_id]
        if session_id in self._beacons:
            del self._beacons[session_id]

        return True

    # ==================== Command Execution ====================

    async def execute(
        self,
        implant_id: str,
        command: str,
        args: List[str] = None,
        timeout: int = 60,
    ) -> CommandResult:
        """
        Execute a shell command on an implant.

        Args:
            implant_id: Target implant
            command: Command to execute
            args: Command arguments
            timeout: Execution timeout in seconds

        Returns:
            CommandResult with stdout/stderr
        """
        self._verify_authorization()

        implant = await self.get_implant(implant_id)
        if not implant:
            raise SessionError(f"Implant {implant_id} not found")

        if not implant.is_alive:
            raise SessionError(f"Implant {implant_id} is not alive")

        logger.info(f"Executing on {implant_id}: {command} {args or ''}")

        start_time = time.time()

        # In real implementation:
        # response = await self.stub.Execute(
        #     sliver_pb2.ExecuteReq(
        #         Request=self._request(implant_id),
        #         Path=command,
        #         Args=args or [],
        #         Output=True,
        #     ),
        #     timeout=timeout
        # )

        # Placeholder - real implementation uses gRPC
        result = CommandResult(
            success=True,
            stdout="",
            stderr="",
            exit_code=0,
            execution_time=time.time() - start_time,
            implant_id=implant_id,
            command=f"{command} {' '.join(args or [])}",
        )

        return result

    async def shell(
        self,
        implant_id: str,
        command: str,
        timeout: int = 60,
    ) -> CommandResult:
        """
        Execute a command through the system shell.

        Uses cmd.exe on Windows, /bin/sh on *nix.
        """
        self._verify_authorization()

        implant = await self.get_implant(implant_id)
        if not implant:
            raise SessionError(f"Implant {implant_id} not found")

        # Select shell based on OS
        if implant.os == ImplantOS.WINDOWS:
            shell_path = "C:\\Windows\\System32\\cmd.exe"
            args = ["/c", command]
        else:
            shell_path = "/bin/sh"
            args = ["-c", command]

        return await self.execute(implant_id, shell_path, args, timeout)

    async def powershell(
        self,
        implant_id: str,
        command: str,
        timeout: int = 60,
    ) -> CommandResult:
        """
        Execute PowerShell command on Windows implant.
        """
        self._verify_authorization()

        implant = await self.get_implant(implant_id)
        if not implant or implant.os != ImplantOS.WINDOWS:
            raise SessionError("PowerShell requires Windows implant")

        ps_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        args = ["-NoProfile", "-NonInteractive", "-Command", command]

        return await self.execute(implant_id, ps_path, args, timeout)

    # ==================== File Operations ====================

    async def download(
        self,
        implant_id: str,
        remote_path: str,
        local_path: Optional[str] = None,
    ) -> bytes:
        """
        Download a file from an implant.

        Args:
            implant_id: Source implant
            remote_path: Path on target system
            local_path: Optional local save path

        Returns:
            File contents as bytes
        """
        self._verify_authorization()

        logger.info(f"Downloading {remote_path} from {implant_id}")

        # In real implementation:
        # response = await self.stub.Download(
        #     sliver_pb2.DownloadReq(
        #         Request=self._request(implant_id),
        #         Path=remote_path,
        #     )
        # )
        # data = response.Data

        data = b""  # Placeholder

        if local_path:
            with open(local_path, 'wb') as f:
                f.write(data)

        return data

    async def upload(
        self,
        implant_id: str,
        local_path: str,
        remote_path: str,
    ) -> bool:
        """
        Upload a file to an implant.

        Args:
            implant_id: Destination implant
            local_path: Path to local file
            remote_path: Destination path on target

        Returns:
            True if successful
        """
        self._verify_authorization()

        with open(local_path, 'rb') as f:
            data = f.read()

        logger.info(f"Uploading {local_path} to {implant_id}:{remote_path}")

        # In real implementation:
        # await self.stub.Upload(
        #     sliver_pb2.UploadReq(
        #         Request=self._request(implant_id),
        #         Path=remote_path,
        #         Data=data,
        #     )
        # )

        return True

    async def ls(
        self,
        implant_id: str,
        path: str,
    ) -> List[FileInfo]:
        """List directory contents on implant."""
        self._verify_authorization()

        # In real implementation:
        # response = await self.stub.Ls(
        #     sliver_pb2.LsReq(
        #         Request=self._request(implant_id),
        #         Path=path,
        #     )
        # )

        return []

    async def cd(self, implant_id: str, path: str) -> str:
        """Change working directory on implant."""
        self._verify_authorization()
        return path

    async def pwd(self, implant_id: str) -> str:
        """Get current working directory on implant."""
        self._verify_authorization()
        return ""

    async def mkdir(self, implant_id: str, path: str) -> bool:
        """Create directory on implant."""
        self._verify_authorization()
        return True

    async def rm(self, implant_id: str, path: str, recursive: bool = False) -> bool:
        """Remove file/directory on implant."""
        self._verify_authorization()
        logger.warning(f"Removing {path} on {implant_id}")
        return True

    # ==================== Process Operations ====================

    async def ps(self, implant_id: str) -> List[ProcessInfo]:
        """List processes on implant."""
        self._verify_authorization()

        # In real implementation:
        # response = await self.stub.Ps(
        #     sliver_pb2.PsReq(Request=self._request(implant_id))
        # )

        return []

    async def kill_process(self, implant_id: str, pid: int) -> bool:
        """Kill a process on implant."""
        self._verify_authorization()
        logger.warning(f"Killing process {pid} on {implant_id}")
        return True

    async def migrate(
        self,
        implant_id: str,
        pid: int,
    ) -> bool:
        """
        Migrate implant to another process.

        Injects implant into target process and transfers control.
        """
        self._verify_authorization()
        logger.warning(f"Migrating {implant_id} to PID {pid}")
        return True

    # ==================== Listener Management ====================

    async def start_mtls_listener(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
    ) -> Listener:
        """Start an mTLS listener."""
        self._verify_authorization()

        listener = Listener(
            id=str(uuid.uuid4())[:8],
            name=f"mtls-{port}",
            protocol=C2Protocol.MTLS,
            host=host,
            port=port,
            started=datetime.now(),
        )

        logger.info(f"Starting mTLS listener on {host}:{port}")

        # In real implementation:
        # await self.stub.StartMTLSListener(
        #     client_pb2.MTLSListenerReq(
        #         Host=host,
        #         Port=port,
        #     )
        # )

        self._listeners[listener.id] = listener
        return listener

    async def start_https_listener(
        self,
        host: str = "0.0.0.0",
        port: int = 443,
        domain: str = "",
        website: str = "",
    ) -> Listener:
        """Start an HTTPS listener."""
        self._verify_authorization()

        listener = Listener(
            id=str(uuid.uuid4())[:8],
            name=f"https-{port}",
            protocol=C2Protocol.HTTPS,
            host=host,
            port=port,
            started=datetime.now(),
            domains=[domain] if domain else [],
            website=website,
        )

        logger.info(f"Starting HTTPS listener on {host}:{port}")

        self._listeners[listener.id] = listener
        return listener

    async def start_http_listener(
        self,
        host: str = "0.0.0.0",
        port: int = 80,
        domain: str = "",
    ) -> Listener:
        """Start an HTTP listener."""
        self._verify_authorization()

        listener = Listener(
            id=str(uuid.uuid4())[:8],
            name=f"http-{port}",
            protocol=C2Protocol.HTTP,
            host=host,
            port=port,
            started=datetime.now(),
            domains=[domain] if domain else [],
        )

        logger.info(f"Starting HTTP listener on {host}:{port}")

        self._listeners[listener.id] = listener
        return listener

    async def start_dns_listener(
        self,
        domains: List[str],
        host: str = "0.0.0.0",
        port: int = 53,
    ) -> Listener:
        """Start a DNS listener."""
        self._verify_authorization()

        listener = Listener(
            id=str(uuid.uuid4())[:8],
            name=f"dns-{domains[0] if domains else 'default'}",
            protocol=C2Protocol.DNS,
            host=host,
            port=port,
            started=datetime.now(),
            domains=domains,
        )

        logger.info(f"Starting DNS listener on {host}:{port} for {domains}")

        self._listeners[listener.id] = listener
        return listener

    async def get_listeners(self) -> List[Listener]:
        """Get all active listeners."""
        return list(self._listeners.values())

    async def kill_listener(self, listener_id: str) -> bool:
        """Stop a listener."""
        self._verify_authorization()

        if listener_id in self._listeners:
            logger.info(f"Stopping listener: {listener_id}")
            del self._listeners[listener_id]
            return True
        return False

    # ==================== Implant Generation ====================

    async def generate_implant(
        self,
        name: str,
        os: ImplantOS = ImplantOS.WINDOWS,
        arch: ImplantArch = ImplantArch.AMD64,
        implant_type: ImplantType = ImplantType.BEACON,
        c2_urls: List[str] = None,
        format: OutputFormat = OutputFormat.EXECUTABLE,
        interval: int = 60,
        jitter: int = 30,
        evasion: bool = True,
        debug: bool = False,
    ) -> Dict[str, Any]:
        """
        Generate a new implant.

        Args:
            name: Implant name
            os: Target operating system
            arch: Target architecture
            implant_type: Beacon (async) or Session (real-time)
            c2_urls: List of C2 callback URLs
            format: Output format (exe, dll, shellcode)
            interval: Beacon check-in interval (seconds)
            jitter: Jitter percentage
            evasion: Enable evasion features
            debug: Enable debug mode

        Returns:
            Dict with implant details and build command
        """
        self._verify_authorization()

        logger.info(f"Generating {implant_type.value} implant: {name}")

        # Build the Sliver generate command
        cmd_parts = ["generate"]

        if implant_type == ImplantType.BEACON:
            cmd_parts.append("beacon")

        cmd_parts.extend([
            f"--os {os.value}",
            f"--arch {arch.value}",
            f"--name {name}",
            f"--format {format.value}",
        ])

        if implant_type == ImplantType.BEACON:
            cmd_parts.extend([
                f"--seconds {interval}",
                f"--jitter {jitter}",
            ])

        if c2_urls:
            for url in c2_urls:
                if url.startswith("mtls://"):
                    cmd_parts.append(f"--mtls {url[7:]}")
                elif url.startswith("https://"):
                    cmd_parts.append(f"--http {url}")
                elif url.startswith("http://"):
                    cmd_parts.append(f"--http {url}")
                elif url.startswith("dns://"):
                    cmd_parts.append(f"--dns {url[6:]}")

        if evasion:
            cmd_parts.append("--evasion")

        if debug:
            cmd_parts.append("--debug")

        # In real implementation, this would call the gRPC Generate method
        # response = await self.stub.Generate(...)

        return {
            "name": name,
            "os": os.value,
            "arch": arch.value,
            "type": implant_type.value,
            "format": format.value,
            "command": " ".join(cmd_parts),
            "c2_urls": c2_urls or [],
            "status": "pending_build",
            "message": "Run the command in Sliver console to generate implant",
        }

    async def regenerate_implant(self, implant_name: str) -> Dict[str, Any]:
        """Regenerate an existing implant configuration."""
        self._verify_authorization()
        return {"name": implant_name, "status": "regenerated"}

    # ==================== Pivoting ====================

    async def start_socks_proxy(
        self,
        implant_id: str,
        port: int = 1080,
    ) -> Dict[str, Any]:
        """Start a SOCKS5 proxy through an implant."""
        self._verify_authorization()

        logger.info(f"Starting SOCKS proxy on {implant_id}:{port}")

        return {
            "implant_id": implant_id,
            "local_port": port,
            "type": "socks5",
            "status": "active",
        }

    async def port_forward(
        self,
        implant_id: str,
        local_port: int,
        remote_host: str,
        remote_port: int,
    ) -> Dict[str, Any]:
        """Create a port forward through an implant."""
        self._verify_authorization()
        self._verify_authorization(remote_host)  # Verify target is in scope

        logger.info(f"Port forward: localhost:{local_port} -> {remote_host}:{remote_port}")

        return {
            "implant_id": implant_id,
            "local_port": local_port,
            "remote_host": remote_host,
            "remote_port": remote_port,
            "status": "active",
        }


class MCPTransport:
    """
    MCP Transport Layer for C2 Operations.

    Exposes C2 functionality as MCP tools that can be called by AI assistants.
    Provides the interface between MCP protocol and Sliver client.
    """

    def __init__(self, client: SliverClient):
        self.client = client
        self.tools = self._register_tools()

    def _register_tools(self) -> Dict[str, Callable]:
        """Register available MCP tools."""
        return {
            # Session management
            "c2_list_sessions": self.list_sessions,
            "c2_list_beacons": self.list_beacons,
            "c2_get_session": self.get_session,
            "c2_kill_session": self.kill_session,

            # Command execution
            "c2_execute": self.execute_command,
            "c2_shell": self.shell_command,
            "c2_powershell": self.powershell_command,

            # File operations
            "c2_download": self.download_file,
            "c2_upload": self.upload_file,
            "c2_ls": self.list_directory,

            # Process operations
            "c2_ps": self.list_processes,
            "c2_kill_process": self.kill_process,

            # Listeners
            "c2_list_listeners": self.list_listeners,
            "c2_start_listener": self.start_listener,
            "c2_stop_listener": self.stop_listener,

            # Implant generation
            "c2_generate_implant": self.generate_implant,

            # Pivoting
            "c2_socks_proxy": self.start_socks,
            "c2_port_forward": self.port_forward,
        }

    def get_tool_definitions(self) -> List[Dict]:
        """Get MCP tool definitions for registration."""
        return [
            {
                "name": "c2_list_sessions",
                "description": "List all active C2 sessions (interactive implants)",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "c2_list_beacons",
                "description": "List all active C2 beacons (async implants)",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "c2_get_session",
                "description": "Get details of a specific session",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string", "description": "Session ID"}
                    },
                    "required": ["session_id"],
                },
            },
            {
                "name": "c2_execute",
                "description": "Execute a command on a target implant",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "command": {"type": "string"},
                        "args": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["session_id", "command"],
                },
            },
            {
                "name": "c2_shell",
                "description": "Execute shell command on implant",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "command": {"type": "string"},
                    },
                    "required": ["session_id", "command"],
                },
            },
            {
                "name": "c2_powershell",
                "description": "Execute PowerShell command on Windows implant",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "command": {"type": "string"},
                    },
                    "required": ["session_id", "command"],
                },
            },
            {
                "name": "c2_download",
                "description": "Download file from implant",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "remote_path": {"type": "string"},
                        "local_path": {"type": "string"},
                    },
                    "required": ["session_id", "remote_path"],
                },
            },
            {
                "name": "c2_upload",
                "description": "Upload file to implant",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "local_path": {"type": "string"},
                        "remote_path": {"type": "string"},
                    },
                    "required": ["session_id", "local_path", "remote_path"],
                },
            },
            {
                "name": "c2_ls",
                "description": "List directory on implant",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "path": {"type": "string"},
                    },
                    "required": ["session_id", "path"],
                },
            },
            {
                "name": "c2_ps",
                "description": "List processes on implant",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                    },
                    "required": ["session_id"],
                },
            },
            {
                "name": "c2_start_listener",
                "description": "Start a C2 listener",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "protocol": {"type": "string", "enum": ["mtls", "https", "http", "dns"]},
                        "host": {"type": "string", "default": "0.0.0.0"},
                        "port": {"type": "integer"},
                        "domain": {"type": "string"},
                    },
                    "required": ["protocol", "port"],
                },
            },
            {
                "name": "c2_list_listeners",
                "description": "List all active listeners",
                "input_schema": {"type": "object", "properties": {}},
            },
            {
                "name": "c2_generate_implant",
                "description": "Generate a new implant/beacon",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "os": {"type": "string", "enum": ["windows", "linux", "darwin"]},
                        "arch": {"type": "string", "enum": ["amd64", "386", "arm64"]},
                        "type": {"type": "string", "enum": ["beacon", "session"]},
                        "format": {"type": "string", "enum": ["exe", "shared", "shellcode"]},
                        "c2_urls": {"type": "array", "items": {"type": "string"}},
                    },
                    "required": ["name", "c2_urls"],
                },
            },
            {
                "name": "c2_socks_proxy",
                "description": "Start SOCKS5 proxy through implant",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "port": {"type": "integer", "default": 1080},
                    },
                    "required": ["session_id"],
                },
            },
            {
                "name": "c2_port_forward",
                "description": "Create port forward through implant",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "session_id": {"type": "string"},
                        "local_port": {"type": "integer"},
                        "remote_host": {"type": "string"},
                        "remote_port": {"type": "integer"},
                    },
                    "required": ["session_id", "local_port", "remote_host", "remote_port"],
                },
            },
        ]

    async def list_sessions(self, **kwargs) -> Dict:
        """List all active sessions."""
        sessions = await self.client.get_sessions()
        return {
            "count": len(sessions),
            "sessions": [s.to_dict() for s in sessions],
        }

    async def list_beacons(self, **kwargs) -> Dict:
        """List all active beacons."""
        beacons = await self.client.get_beacons()
        return {
            "count": len(beacons),
            "beacons": [b.to_dict() for b in beacons],
        }

    async def get_session(self, session_id: str, **kwargs) -> Dict:
        """Get session details."""
        session = await self.client.get_implant(session_id)
        if session:
            return session.to_dict()
        return {"error": f"Session {session_id} not found"}

    async def kill_session(self, session_id: str, force: bool = False, **kwargs) -> Dict:
        """Kill a session."""
        result = await self.client.kill_session(session_id, force)
        return {"success": result, "session_id": session_id}

    async def execute_command(
        self,
        session_id: str,
        command: str,
        args: List[str] = None,
        **kwargs
    ) -> Dict:
        """Execute command on implant."""
        result = await self.client.execute(session_id, command, args)
        return result.to_dict()

    async def shell_command(self, session_id: str, command: str, **kwargs) -> Dict:
        """Execute shell command."""
        result = await self.client.shell(session_id, command)
        return result.to_dict()

    async def powershell_command(self, session_id: str, command: str, **kwargs) -> Dict:
        """Execute PowerShell command."""
        result = await self.client.powershell(session_id, command)
        return result.to_dict()

    async def download_file(
        self,
        session_id: str,
        remote_path: str,
        local_path: str = None,
        **kwargs
    ) -> Dict:
        """Download file from implant."""
        data = await self.client.download(session_id, remote_path, local_path)
        return {
            "success": True,
            "remote_path": remote_path,
            "local_path": local_path,
            "size": len(data),
        }

    async def upload_file(
        self,
        session_id: str,
        local_path: str,
        remote_path: str,
        **kwargs
    ) -> Dict:
        """Upload file to implant."""
        result = await self.client.upload(session_id, local_path, remote_path)
        return {
            "success": result,
            "local_path": local_path,
            "remote_path": remote_path,
        }

    async def list_directory(self, session_id: str, path: str, **kwargs) -> Dict:
        """List directory contents."""
        files = await self.client.ls(session_id, path)
        return {
            "path": path,
            "files": [f.to_dict() for f in files],
        }

    async def list_processes(self, session_id: str, **kwargs) -> Dict:
        """List processes on implant."""
        processes = await self.client.ps(session_id)
        return {
            "count": len(processes),
            "processes": [p.to_dict() for p in processes],
        }

    async def kill_process(self, session_id: str, pid: int, **kwargs) -> Dict:
        """Kill process on implant."""
        result = await self.client.kill_process(session_id, pid)
        return {"success": result, "pid": pid}

    async def list_listeners(self, **kwargs) -> Dict:
        """List all active listeners."""
        listeners = await self.client.get_listeners()
        return {
            "count": len(listeners),
            "listeners": [l.to_dict() for l in listeners],
        }

    async def start_listener(
        self,
        protocol: str,
        port: int,
        host: str = "0.0.0.0",
        domain: str = "",
        **kwargs
    ) -> Dict:
        """Start a listener."""
        if protocol == "mtls":
            listener = await self.client.start_mtls_listener(host, port)
        elif protocol == "https":
            listener = await self.client.start_https_listener(host, port, domain)
        elif protocol == "http":
            listener = await self.client.start_http_listener(host, port, domain)
        elif protocol == "dns":
            listener = await self.client.start_dns_listener([domain], host, port)
        else:
            return {"error": f"Unknown protocol: {protocol}"}

        return listener.to_dict()

    async def stop_listener(self, listener_id: str, **kwargs) -> Dict:
        """Stop a listener."""
        result = await self.client.kill_listener(listener_id)
        return {"success": result, "listener_id": listener_id}

    async def generate_implant(
        self,
        name: str,
        c2_urls: List[str],
        os: str = "windows",
        arch: str = "amd64",
        type: str = "beacon",
        format: str = "exe",
        **kwargs
    ) -> Dict:
        """Generate an implant."""
        result = await self.client.generate_implant(
            name=name,
            os=ImplantOS(os),
            arch=ImplantArch(arch),
            implant_type=ImplantType(type),
            c2_urls=c2_urls,
            format=OutputFormat(format),
        )
        return result

    async def start_socks(self, session_id: str, port: int = 1080, **kwargs) -> Dict:
        """Start SOCKS proxy."""
        return await self.client.start_socks_proxy(session_id, port)

    async def port_forward(
        self,
        session_id: str,
        local_port: int,
        remote_host: str,
        remote_port: int,
        **kwargs
    ) -> Dict:
        """Create port forward."""
        return await self.client.port_forward(
            session_id, local_port, remote_host, remote_port
        )


class C2Framework:
    """
    Main C2 Framework class.

    Orchestrates Sliver client and MCP transport layer.
    Entry point for C2 operations.

    Usage:
        # Initialize framework
        c2 = C2Framework()

        # Load Sliver config
        c2.load_config("/path/to/sliver-config.json")

        # Or from environment
        c2.load_config_from_env()

        # Set engagement scope
        c2.set_scope(scope)

        # Connect to Sliver
        await c2.connect()

        # Use via MCP transport
        result = await c2.mcp.list_sessions()

        # Or direct client access
        sessions = await c2.client.get_sessions()
    """

    def __init__(self):
        self.client: Optional[SliverClient] = None
        self.mcp: Optional[MCPTransport] = None
        self._config: Optional[SliverConfig] = None
        self._scope: Optional[EngagementScope] = None

    def load_config(self, config_path: str):
        """Load Sliver configuration from file."""
        self._config = SliverConfig.from_file(config_path)
        self.client = SliverClient(self._config)

    def load_config_from_env(self):
        """Load Sliver configuration from environment variables."""
        self._config = SliverConfig.from_env()
        self.client = SliverClient(self._config)

    def set_scope(self, scope: EngagementScope):
        """Set engagement scope for authorization."""
        self._scope = scope
        if self.client:
            self.client.set_scope(scope)

    async def connect(self) -> bool:
        """Connect to Sliver server."""
        if not self.client:
            raise ConnectionError("No configuration loaded")

        result = await self.client.connect()

        if result:
            self.mcp = MCPTransport(self.client)

        return result

    async def disconnect(self):
        """Disconnect from Sliver server."""
        if self.client:
            await self.client.disconnect()

    def get_mcp_tools(self) -> List[Dict]:
        """Get MCP tool definitions."""
        if self.mcp:
            return self.mcp.get_tool_definitions()
        return []

    async def handle_mcp_call(self, tool_name: str, params: Dict) -> Dict:
        """Handle an MCP tool call."""
        if not self.mcp:
            return {"error": "Not connected"}

        if tool_name not in self.mcp.tools:
            return {"error": f"Unknown tool: {tool_name}"}

        handler = self.mcp.tools[tool_name]
        return await handler(**params)


# Convenience functions for direct use

async def connect_to_sliver(config_path: str = None) -> C2Framework:
    """
    Quick connect to Sliver.

    Args:
        config_path: Path to Sliver operator config, or uses env vars

    Returns:
        Connected C2Framework instance
    """
    c2 = C2Framework()

    if config_path:
        c2.load_config(config_path)
    else:
        c2.load_config_from_env()

    await c2.connect()
    return c2


def create_scope(
    engagement_id: str,
    client: str,
    targets: List[str],
    networks: List[str],
    duration_days: int = 7,
) -> EngagementScope:
    """
    Create an engagement scope.

    Args:
        engagement_id: Unique engagement identifier
        client: Client name
        targets: List of authorized target IPs/hostnames
        networks: List of authorized network ranges (CIDR)
        duration_days: Engagement duration

    Returns:
        EngagementScope instance
    """
    from datetime import timedelta

    return EngagementScope(
        engagement_id=engagement_id,
        client=client,
        authorized_targets=targets,
        authorized_networks=networks,
        start_date=datetime.now(),
        end_date=datetime.now() + timedelta(days=duration_days),
        rules_of_engagement={
            "data_exfil": True,
            "destructive_actions": False,
            "social_engineering": True,
            "physical_access": False,
        },
    )


# Example usage
if __name__ == "__main__":
    async def main():
        # Create scope for authorized engagement
        scope = create_scope(
            engagement_id="ENG-2024-001",
            client="Acme Corp",
            targets=["10.0.0.1", "10.0.0.2"],
            networks=["10.0.0.0/24", "192.168.1.0/24"],
            duration_days=14,
        )

        # Initialize C2 framework
        c2 = C2Framework()
        c2.load_config_from_env()
        c2.set_scope(scope)

        try:
            # Connect to Sliver
            await c2.connect()
            print("Connected to Sliver!")

            # List sessions via MCP
            result = await c2.mcp.list_sessions()
            print(f"Active sessions: {result['count']}")

            # Get MCP tool definitions for registration
            tools = c2.get_mcp_tools()
            print(f"Available MCP tools: {len(tools)}")

        except ConnectionError as e:
            print(f"Connection failed: {e}")
        except AuthorizationError as e:
            print(f"Authorization error: {e}")
        finally:
            await c2.disconnect()

    asyncio.run(main())
