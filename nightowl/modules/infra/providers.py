"""
Cloud provider abstractions for ephemeral infrastructure.
"""
import os
import requests
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

class CloudProvider(ABC):
    @abstractmethod
    def create_server(self, name: str, region: str, size: str, image: str) -> Dict:
        pass
    
    @abstractmethod
    def destroy_server(self, server_id: str) -> bool:
        pass
    
    @abstractmethod
    def list_servers(self) -> List[Dict]:
        pass
    
    @abstractmethod
    def get_server_ip(self, server_id: str) -> str:
        pass


class DigitalOceanProvider(CloudProvider):
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("DO_API_KEY")
        self.base_url = "https://api.digitalocean.com/v2"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    def create_server(
        self, 
        name: str, 
        region: str = "nyc1", 
        size: str = "s-1vcpu-1gb",
        image: str = "ubuntu-22-04-x64"
    ) -> Dict:
        """Create DigitalOcean droplet."""
        data = {
            "name": name,
            "region": region,
            "size": size,
            "image": image,
            "ssh_keys": [],  # Add your SSH key IDs
            "backups": False,
            "ipv6": False,
        }
        
        resp = requests.post(
            f"{self.base_url}/droplets",
            headers=self.headers,
            json=data
        )
        
        if resp.status_code == 202:
            droplet = resp.json()["droplet"]
            return {
                "id": droplet["id"],
                "name": droplet["name"],
                "status": "creating",
                "provider": "digitalocean"
            }
        
        return {"error": resp.text}
    
    def destroy_server(self, server_id: str) -> bool:
        """Destroy droplet."""
        resp = requests.delete(
            f"{self.base_url}/droplets/{server_id}",
            headers=self.headers
        )
        return resp.status_code == 204
    
    def list_servers(self) -> List[Dict]:
        """List all droplets."""
        resp = requests.get(
            f"{self.base_url}/droplets",
            headers=self.headers
        )
        if resp.status_code == 200:
            return resp.json().get("droplets", [])
        return []
    
    def get_server_ip(self, server_id: str) -> str:
        """Get droplet IP."""
        resp = requests.get(
            f"{self.base_url}/droplets/{server_id}",
            headers=self.headers
        )
        if resp.status_code == 200:
            networks = resp.json()["droplet"]["networks"]["v4"]
            for net in networks:
                if net["type"] == "public":
                    return net["ip_address"]
        return ""
    
    def wait_for_ready(self, server_id: str, timeout: int = 120) -> bool:
        """Wait for droplet to be active."""
        start = time.time()
        while time.time() - start < timeout:
            resp = requests.get(
                f"{self.base_url}/droplets/{server_id}",
                headers=self.headers
            )
            if resp.status_code == 200:
                status = resp.json()["droplet"]["status"]
                if status == "active":
                    return True
            time.sleep(5)
        return False


class LinodeProvider(CloudProvider):
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("LINODE_API_KEY")
        self.base_url = "https://api.linode.com/v4"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    def create_server(
        self,
        name: str,
        region: str = "us-east",
        size: str = "g6-nanode-1",
        image: str = "linode/ubuntu22.04"
    ) -> Dict:
        data = {
            "label": name,
            "region": region,
            "type": size,
            "image": image,
            "root_pass": os.urandom(16).hex(),  # Random password
        }
        
        resp = requests.post(
            f"{self.base_url}/linode/instances",
            headers=self.headers,
            json=data
        )
        
        if resp.status_code == 200:
            instance = resp.json()
            return {
                "id": instance["id"],
                "name": instance["label"],
                "status": instance["status"],
                "provider": "linode"
            }
        
        return {"error": resp.text}
    
    def destroy_server(self, server_id: str) -> bool:
        resp = requests.delete(
            f"{self.base_url}/linode/instances/{server_id}",
            headers=self.headers
        )
        return resp.status_code == 200
    
    def list_servers(self) -> List[Dict]:
        resp = requests.get(
            f"{self.base_url}/linode/instances",
            headers=self.headers
        )
        if resp.status_code == 200:
            return resp.json().get("data", [])
        return []
    
    def get_server_ip(self, server_id: str) -> str:
        resp = requests.get(
            f"{self.base_url}/linode/instances/{server_id}",
            headers=self.headers
        )
        if resp.status_code == 200:
            return resp.json().get("ipv4", [""])[0]
        return ""


class VultrProvider(CloudProvider):
    """Vultr cloud provider."""
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("VULTR_API_KEY")
        self.base_url = "https://api.vultr.com/v2"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    def create_server(
        self,
        name: str,
        region: str = "ewr",  # New Jersey
        size: str = "vc2-1c-1gb",
        image: str = "ubuntu_22_04_x64"
    ) -> Dict:
        # Get OS ID
        os_id = self._get_os_id(image)
        
        data = {
            "region": region,
            "plan": size,
            "os_id": os_id,
            "label": name,
        }
        
        resp = requests.post(
            f"{self.base_url}/instances",
            headers=self.headers,
            json=data
        )
        
        if resp.status_code == 202:
            instance = resp.json()["instance"]
            return {
                "id": instance["id"],
                "name": instance["label"],
                "status": instance["status"],
                "provider": "vultr"
            }
        
        return {"error": resp.text}
    
    def _get_os_id(self, image: str) -> int:
        """Map image name to Vultr OS ID."""
        os_map = {
            "ubuntu_22_04_x64": 1743,
            "debian_11_x64": 477,
            "centos_8_x64": 362,
        }
        return os_map.get(image, 1743)
    
    def destroy_server(self, server_id: str) -> bool:
        resp = requests.delete(
            f"{self.base_url}/instances/{server_id}",
            headers=self.headers
        )
        return resp.status_code == 204
    
    def list_servers(self) -> List[Dict]:
        resp = requests.get(
            f"{self.base_url}/instances",
            headers=self.headers
        )
        if resp.status_code == 200:
            return resp.json().get("instances", [])
        return []
    
    def get_server_ip(self, server_id: str) -> str:
        resp = requests.get(
            f"{self.base_url}/instances/{server_id}",
            headers=self.headers
        )
        if resp.status_code == 200:
            return resp.json()["instance"].get("main_ip", "")
        return ""


class AWSLightsailProvider(CloudProvider):
    """AWS Lightsail for quick VPS deployment."""
    def __init__(self, region: str = "us-east-1"):
        import boto3
        self.client = boto3.client("lightsail", region_name=region)
        self.region = region
    
    def create_server(
        self,
        name: str,
        region: str = None,
        size: str = "nano_2_0",
        image: str = "ubuntu_22_04"
    ) -> Dict:
        try:
            response = self.client.create_instances(
                instanceNames=[name],
                availabilityZone=f"{region or self.region}a",
                blueprintId=image,
                bundleId=size,
            )
            
            if response["operations"]:
                return {
                    "id": name,  # Lightsail uses name as ID
                    "name": name,
                    "status": "creating",
                    "provider": "aws_lightsail"
                }
        except Exception as e:
            return {"error": str(e)}
        
        return {"error": "Unknown error"}
    
    def destroy_server(self, server_id: str) -> bool:
        try:
            self.client.delete_instance(instanceName=server_id)
            return True
        except:
            return False
    
    def list_servers(self) -> List[Dict]:
        try:
            response = self.client.get_instances()
            return response.get("instances", [])
        except:
            return []
    
    def get_server_ip(self, server_id: str) -> str:
        try:
            response = self.client.get_instance(instanceName=server_id)
            return response["instance"].get("publicIpAddress", "")
        except:
            return ""


def get_provider(name: str, **kwargs) -> CloudProvider:
    """Factory function to get provider by name."""
    providers = {
        "digitalocean": DigitalOceanProvider,
        "linode": LinodeProvider,
        "vultr": VultrProvider,
        "aws_lightsail": AWSLightsailProvider,
    }
    
    if name not in providers:
        raise ValueError(f"Unknown provider: {name}. Available: {list(providers.keys())}")
    
    return providers[name](**kwargs)
