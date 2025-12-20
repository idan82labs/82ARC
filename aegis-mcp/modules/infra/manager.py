"""
Infrastructure manager for ephemeral C2.
"""
import os
import json
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Optional
from .providers import get_provider, CloudProvider

class InfrastructureManager:
    def __init__(self, provider: str = "digitalocean", **provider_kwargs):
        self.provider_name = provider
        self.provider = get_provider(provider, **provider_kwargs)
        self.active_infra = {}
        self.state_file = None  # Optional persistent state
    
    def deploy_c2_stack(
        self,
        operation_id: str,
        region: str = None,
        redirector_count: int = 1,
        c2_type: str = "sliver"
    ) -> Dict:
        """Deploy complete C2 infrastructure stack."""
        
        stack = {
            "operation_id": operation_id,
            "created_at": datetime.utcnow().isoformat(),
            "provider": self.provider_name,
            "c2_type": c2_type,
            "servers": {},
            "dns_records": [],
            "status": "deploying"
        }
        
        # Deploy main C2 server
        print(f"[*] Deploying C2 server for operation {operation_id}")
        c2_server = self.provider.create_server(
            name=f"c2-{operation_id}",
            region=region or self._default_region()
        )
        
        if "error" not in c2_server:
            stack["servers"]["c2"] = c2_server
            if hasattr(self.provider, 'wait_for_ready'):
                self.provider.wait_for_ready(c2_server["id"])
            c2_server["ip"] = self.provider.get_server_ip(c2_server["id"])
            print(f"[+] C2 server: {c2_server['ip']}")
        else:
            stack["status"] = "failed"
            stack["error"] = c2_server["error"]
            return stack
        
        # Deploy redirectors
        for i in range(redirector_count):
            print(f"[*] Deploying redirector {i+1}/{redirector_count}")
            redir = self.provider.create_server(
                name=f"redir-{operation_id}-{i}",
                region=region or self._default_region()
            )
            if "error" not in redir:
                stack["servers"][f"redirector_{i}"] = redir
                if hasattr(self.provider, 'wait_for_ready'):
                    self.provider.wait_for_ready(redir["id"])
                redir["ip"] = self.provider.get_server_ip(redir["id"])
                print(f"[+] Redirector {i}: {redir['ip']}")
        
        stack["status"] = "active"
        self.active_infra[operation_id] = stack
        
        return stack
    
    def _default_region(self) -> str:
        """Return default region for provider."""
        defaults = {
            "digitalocean": "nyc1",
            "linode": "us-east",
            "vultr": "ewr",
            "aws_lightsail": "us-east-1"
        }
        return defaults.get(self.provider_name, "us-east")
    
    def burn_stack(self, operation_id: str) -> Dict:
        """Destroy all infrastructure for operation."""
        
        if operation_id not in self.active_infra:
            return {"error": "Operation not found"}
        
        stack = self.active_infra[operation_id]
        results = {"destroyed": [], "failed": []}
        
        print(f"[*] Burning infrastructure for {operation_id}")
        
        for name, server in stack["servers"].items():
            print(f"[*] Destroying {name} ({server['id']})")
            if self.provider.destroy_server(str(server["id"])):
                results["destroyed"].append(name)
                print(f"[+] {name} destroyed")
            else:
                results["failed"].append(name)
                print(f"[-] Failed to destroy {name}")
        
        del self.active_infra[operation_id]
        
        return results
    
    def get_stack_status(self, operation_id: str) -> Dict:
        """Get current stack status."""
        return self.active_infra.get(operation_id, {"error": "Not found"})
    
    def list_active_operations(self) -> List[str]:
        """List all active operations."""
        return list(self.active_infra.keys())
    
    def burn_all(self) -> Dict:
        """Emergency: destroy all infrastructure."""
        print("[!] EMERGENCY BURN - destroying all infrastructure")
        results = {}
        for op_id in list(self.active_infra.keys()):
            results[op_id] = self.burn_stack(op_id)
        return results
    
    def get_connection_info(self, operation_id: str) -> Dict:
        """Get connection details for operation."""
        if operation_id not in self.active_infra:
            return {"error": "Not found"}
        
        stack = self.active_infra[operation_id]
        info = {
            "c2_ip": stack["servers"].get("c2", {}).get("ip"),
            "redirectors": [],
            "c2_type": stack.get("c2_type", "unknown")
        }
        
        for key, server in stack["servers"].items():
            if key.startswith("redirector"):
                info["redirectors"].append(server.get("ip"))
        
        return info


class C2Configurator:
    """Configure deployed C2 servers."""
    
    def __init__(self):
        self.setup_scripts = {
            "sliver": self._sliver_setup(),
            "mythic": self._mythic_setup(),
            "cobalt": self._cobalt_setup(),
            "havoc": self._havoc_setup(),
            "covenant": self._covenant_setup(),
        }
    
    def _sliver_setup(self) -> str:
        return '''#!/bin/bash
set -e
apt-get update
apt-get install -y curl

# Install Sliver
curl https://sliver.sh/install | bash

# Generate configs
sliver-server daemon &
sleep 5

# Create operator config
sliver-server operator --name operator --lhost 0.0.0.0 --save /root/operator.cfg

echo "[+] Sliver installed. Operator config at /root/operator.cfg"
'''
    
    def _mythic_setup(self) -> str:
        return '''#!/bin/bash
set -e
apt-get update
apt-get install -y docker.io docker-compose git make

# Clone Mythic
cd /opt
git clone https://github.com/its-a-feature/Mythic
cd Mythic

# Install
./install_docker_ubuntu.sh
make

# Start
./mythic-cli start

# Get password
./mythic-cli config get admin_password

echo "[+] Mythic installed at https://$(hostname -I | awk '{print $1}'):7443"
'''
    
    def _cobalt_setup(self) -> str:
        return '''#!/bin/bash
# Cobalt Strike requires license
# Upload your cobaltstrike.jar and license to /opt/cobaltstrike/
# Then run:
# cd /opt/cobaltstrike && ./teamserver $(hostname -I | awk '{print $1}') <password>
echo "[-] Cobalt Strike requires manual license setup"
'''
    
    def _havoc_setup(self) -> str:
        return '''#!/bin/bash
set -e
apt-get update
apt-get install -y git build-essential apt-utils cmake libfontconfig1 libglu1-mesa-dev libgtest-dev libspdlog-dev libboost-all-dev libncurses5-dev libgdbm-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev libbz2-dev mesa-common-dev qtbase5-dev qtchooser qt5-qmake qtbase5-dev-tools libqt5websockets5 libqt5websockets5-dev qtdeclarative5-dev golang-go qtbase5-dev nasm

cd /opt
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc

# Build teamserver
cd teamserver
go mod download golang.org/x/sys
go mod download github.com/ugorji/go
make
./teamserver server --profile ./profiles/havoc.yaotl -v --debug &

echo "[+] Havoc teamserver starting"
'''
    
    def _covenant_setup(self) -> str:
        return '''#!/bin/bash
set -e
apt-get update
apt-get install -y docker.io

docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v /opt/covenant-data:/app/Data covenantproject/covenant

echo "[+] Covenant running on port 7443"
'''
    
    def configure_server(
        self,
        ip: str,
        c2_type: str,
        ssh_key_path: str = None,
        ssh_password: str = None
    ) -> Dict:
        """SSH to server and configure C2."""
        import paramiko
        
        script = self.setup_scripts.get(c2_type)
        if not script:
            return {"error": f"Unknown C2 type: {c2_type}"}
        
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {"hostname": ip, "username": "root"}
            if ssh_key_path:
                connect_kwargs["key_filename"] = ssh_key_path
            elif ssh_password:
                connect_kwargs["password"] = ssh_password
            
            ssh.connect(**connect_kwargs)
            
            # Upload and execute script
            sftp = ssh.open_sftp()
            with sftp.file("/tmp/setup.sh", "w") as f:
                f.write(script)
            sftp.close()
            
            stdin, stdout, stderr = ssh.exec_command("chmod +x /tmp/setup.sh && /tmp/setup.sh")
            output = stdout.read().decode()
            errors = stderr.read().decode()
            
            ssh.close()
            
            return {
                "success": True,
                "output": output,
                "errors": errors
            }
        except Exception as e:
            return {"error": str(e)}
    
    def configure_redirector(
        self,
        ip: str,
        c2_ip: str,
        c2_port: int = 443,
        ssh_key_path: str = None,
        ssh_password: str = None
    ) -> Dict:
        """Configure redirector to forward traffic to C2."""
        
        script = f'''#!/bin/bash
set -e
apt-get update
apt-get install -y socat iptables-persistent

# Simple socat redirector
nohup socat TCP-LISTEN:443,fork TCP:{c2_ip}:{c2_port} &
nohup socat TCP-LISTEN:80,fork TCP:{c2_ip}:80 &

# Or use iptables
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination {c2_ip}:{c2_port}
iptables -t nat -A POSTROUTING -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward

echo "[+] Redirector configured: {ip} -> {c2_ip}:{c2_port}"
'''
        
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            connect_kwargs = {"hostname": ip, "username": "root"}
            if ssh_key_path:
                connect_kwargs["key_filename"] = ssh_key_path
            elif ssh_password:
                connect_kwargs["password"] = ssh_password
            
            ssh.connect(**connect_kwargs)
            
            stdin, stdout, stderr = ssh.exec_command(script)
            output = stdout.read().decode()
            
            ssh.close()
            return {"success": True, "output": output}
        except Exception as e:
            return {"error": str(e)}


class OperationOrchestrator:
    """High-level operation management."""
    
    def __init__(self, provider: str = "digitalocean"):
        self.infra = InfrastructureManager(provider)
        self.configurator = C2Configurator()
    
    def full_deploy(
        self,
        operation_id: str,
        c2_type: str = "sliver",
        region: str = None,
        redirector_count: int = 2,
        ssh_key_path: str = None
    ) -> Dict:
        """Deploy and configure full C2 stack."""
        
        result = {
            "operation_id": operation_id,
            "status": "deploying",
            "steps": []
        }
        
        # Step 1: Deploy infrastructure
        print(f"[*] Step 1: Deploying infrastructure")
        stack = self.infra.deploy_c2_stack(
            operation_id=operation_id,
            region=region,
            redirector_count=redirector_count,
            c2_type=c2_type
        )
        result["steps"].append({"deploy_infra": stack["status"]})
        
        if stack["status"] != "active":
            result["status"] = "failed"
            return result
        
        # Wait for servers to be SSH-ready
        print("[*] Waiting for SSH availability...")
        time.sleep(30)
        
        # Step 2: Configure C2
        if ssh_key_path:
            c2_ip = stack["servers"]["c2"]["ip"]
            print(f"[*] Step 2: Configuring C2 at {c2_ip}")
            c2_config = self.configurator.configure_server(
                ip=c2_ip,
                c2_type=c2_type,
                ssh_key_path=ssh_key_path
            )
            result["steps"].append({"configure_c2": c2_config.get("success", False)})
            
            # Step 3: Configure redirectors
            for key, server in stack["servers"].items():
                if key.startswith("redirector"):
                    print(f"[*] Step 3: Configuring {key}")
                    redir_config = self.configurator.configure_redirector(
                        ip=server["ip"],
                        c2_ip=c2_ip,
                        ssh_key_path=ssh_key_path
                    )
                    result["steps"].append({f"configure_{key}": redir_config.get("success", False)})
        
        result["status"] = "active"
        result["connection_info"] = self.infra.get_connection_info(operation_id)
        
        return result
    
    def teardown(self, operation_id: str) -> Dict:
        """Complete teardown of operation."""
        return self.infra.burn_stack(operation_id)
    
    def emergency_burn(self) -> Dict:
        """Emergency destroy all."""
        return self.infra.burn_all()
