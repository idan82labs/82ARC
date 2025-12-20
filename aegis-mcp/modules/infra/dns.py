"""
DNS management for C2 infrastructure.
"""
import os
import requests
import time
from typing import Dict, List, Optional

class CloudflareDNS:
    def __init__(self, api_key: str = None, zone_id: str = None):
        self.api_key = api_key or os.environ.get("CF_API_KEY")
        self.zone_id = zone_id or os.environ.get("CF_ZONE_ID")
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    def create_record(
        self,
        name: str,
        content: str,
        record_type: str = "A",
        proxied: bool = False,
        ttl: int = 1  # 1 = auto
    ) -> Dict:
        """Create DNS record."""
        data = {
            "type": record_type,
            "name": name,
            "content": content,
            "proxied": proxied,
            "ttl": ttl
        }
        
        resp = requests.post(
            f"{self.base_url}/zones/{self.zone_id}/dns_records",
            headers=self.headers,
            json=data
        )
        
        if resp.status_code == 200:
            result = resp.json()["result"]
            return {
                "id": result["id"],
                "name": result["name"],
                "content": result["content"],
                "type": result["type"]
            }
        return {"error": resp.text}
    
    def delete_record(self, record_id: str) -> bool:
        """Delete DNS record."""
        resp = requests.delete(
            f"{self.base_url}/zones/{self.zone_id}/dns_records/{record_id}",
            headers=self.headers
        )
        return resp.status_code == 200
    
    def list_records(self, name: str = None, record_type: str = None) -> List[Dict]:
        """List DNS records."""
        params = {}
        if name:
            params["name"] = name
        if record_type:
            params["type"] = record_type
        
        resp = requests.get(
            f"{self.base_url}/zones/{self.zone_id}/dns_records",
            headers=self.headers,
            params=params
        )
        
        if resp.status_code == 200:
            return resp.json()["result"]
        return []
    
    def update_record(
        self,
        record_id: str,
        content: str,
        name: str = None,
        record_type: str = None,
        proxied: bool = None
    ) -> Dict:
        """Update existing DNS record."""
        # First get current record
        resp = requests.get(
            f"{self.base_url}/zones/{self.zone_id}/dns_records/{record_id}",
            headers=self.headers
        )
        
        if resp.status_code != 200:
            return {"error": "Record not found"}
        
        current = resp.json()["result"]
        
        data = {
            "type": record_type or current["type"],
            "name": name or current["name"],
            "content": content,
            "proxied": proxied if proxied is not None else current["proxied"],
            "ttl": current["ttl"]
        }
        
        resp = requests.put(
            f"{self.base_url}/zones/{self.zone_id}/dns_records/{record_id}",
            headers=self.headers,
            json=data
        )
        
        if resp.status_code == 200:
            return resp.json()["result"]
        return {"error": resp.text}
    
    def get_zone_id(self, domain: str) -> Optional[str]:
        """Get zone ID for domain."""
        resp = requests.get(
            f"{self.base_url}/zones",
            headers=self.headers,
            params={"name": domain}
        )
        
        if resp.status_code == 200:
            zones = resp.json()["result"]
            if zones:
                return zones[0]["id"]
        return None


class NamecheapDNS:
    """Namecheap DNS management."""
    
    def __init__(self, api_user: str = None, api_key: str = None, username: str = None):
        self.api_user = api_user or os.environ.get("NC_API_USER")
        self.api_key = api_key or os.environ.get("NC_API_KEY")
        self.username = username or os.environ.get("NC_USERNAME")
        self.base_url = "https://api.namecheap.com/xml.response"
        self.client_ip = self._get_public_ip()
    
    def _get_public_ip(self) -> str:
        """Get public IP for API whitelist."""
        try:
            return requests.get("https://api.ipify.org").text
        except:
            return "127.0.0.1"
    
    def _make_request(self, command: str, params: dict = None) -> Dict:
        """Make API request to Namecheap."""
        base_params = {
            "ApiUser": self.api_user,
            "ApiKey": self.api_key,
            "UserName": self.username,
            "ClientIp": self.client_ip,
            "Command": command
        }
        if params:
            base_params.update(params)
        
        resp = requests.get(self.base_url, params=base_params)
        # Would need XML parsing here
        return {"raw": resp.text}
    
    def set_hosts(self, domain: str, sld: str, tld: str, hosts: List[Dict]) -> Dict:
        """Set DNS hosts for domain."""
        params = {
            "SLD": sld,
            "TLD": tld
        }
        
        for i, host in enumerate(hosts):
            params[f"HostName{i+1}"] = host.get("name", "@")
            params[f"RecordType{i+1}"] = host.get("type", "A")
            params[f"Address{i+1}"] = host.get("address")
            params[f"TTL{i+1}"] = host.get("ttl", 1800)
        
        return self._make_request("namecheap.domains.dns.setHosts", params)


class Route53DNS:
    """AWS Route53 DNS management."""
    
    def __init__(self, hosted_zone_id: str = None):
        import boto3
        self.client = boto3.client("route53")
        self.hosted_zone_id = hosted_zone_id or os.environ.get("R53_ZONE_ID")
    
    def create_record(
        self,
        name: str,
        content: str,
        record_type: str = "A",
        ttl: int = 300
    ) -> Dict:
        """Create Route53 record."""
        try:
            response = self.client.change_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                ChangeBatch={
                    "Changes": [{
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": name,
                            "Type": record_type,
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": content}]
                        }
                    }]
                }
            )
            return {"id": response["ChangeInfo"]["Id"], "status": response["ChangeInfo"]["Status"]}
        except Exception as e:
            return {"error": str(e)}
    
    def delete_record(
        self,
        name: str,
        content: str,
        record_type: str = "A",
        ttl: int = 300
    ) -> bool:
        """Delete Route53 record."""
        try:
            self.client.change_resource_record_sets(
                HostedZoneId=self.hosted_zone_id,
                ChangeBatch={
                    "Changes": [{
                        "Action": "DELETE",
                        "ResourceRecordSet": {
                            "Name": name,
                            "Type": record_type,
                            "TTL": ttl,
                            "ResourceRecords": [{"Value": content}]
                        }
                    }]
                }
            )
            return True
        except:
            return False
    
    def list_records(self) -> List[Dict]:
        """List all records in zone."""
        try:
            response = self.client.list_resource_record_sets(
                HostedZoneId=self.hosted_zone_id
            )
            return response.get("ResourceRecordSets", [])
        except:
            return []


class DNSManager:
    """Unified DNS management across providers."""
    
    def __init__(self, provider: str = "cloudflare", **kwargs):
        self.provider_name = provider
        
        if provider == "cloudflare":
            self.provider = CloudflareDNS(**kwargs)
        elif provider == "route53":
            self.provider = Route53DNS(**kwargs)
        elif provider == "namecheap":
            self.provider = NamecheapDNS(**kwargs)
        else:
            raise ValueError(f"Unknown DNS provider: {provider}")
        
        self.managed_records = {}
    
    def setup_c2_dns(
        self,
        operation_id: str,
        domain: str,
        c2_ip: str,
        redirector_ips: List[str] = None
    ) -> Dict:
        """Setup DNS for C2 operation."""
        
        records = {"created": [], "failed": []}
        
        # Main C2 subdomain
        c2_record = self.provider.create_record(
            name=f"c2-{operation_id}.{domain}",
            content=c2_ip,
            record_type="A"
        )
        
        if "error" not in c2_record:
            records["created"].append(c2_record)
            self.managed_records[f"c2-{operation_id}"] = c2_record.get("id")
        else:
            records["failed"].append({"name": f"c2-{operation_id}", "error": c2_record["error"]})
        
        # Redirector subdomains
        if redirector_ips:
            for i, ip in enumerate(redirector_ips):
                redir_record = self.provider.create_record(
                    name=f"r{i}-{operation_id}.{domain}",
                    content=ip,
                    record_type="A"
                )
                
                if "error" not in redir_record:
                    records["created"].append(redir_record)
                    self.managed_records[f"r{i}-{operation_id}"] = redir_record.get("id")
                else:
                    records["failed"].append({"name": f"r{i}-{operation_id}", "error": redir_record["error"]})
        
        return records
    
    def cleanup_c2_dns(self, operation_id: str) -> Dict:
        """Remove all DNS records for operation."""
        
        results = {"deleted": [], "failed": []}
        
        # Find all records for this operation
        keys_to_delete = [k for k in self.managed_records.keys() if operation_id in k]
        
        for key in keys_to_delete:
            record_id = self.managed_records[key]
            if self.provider.delete_record(record_id):
                results["deleted"].append(key)
                del self.managed_records[key]
            else:
                results["failed"].append(key)
        
        return results
    
    def create_fronting_records(
        self,
        operation_id: str,
        domain: str,
        cdn_endpoint: str
    ) -> Dict:
        """Create records for domain fronting."""
        
        # Create CNAME to CDN
        record = self.provider.create_record(
            name=f"cdn-{operation_id}.{domain}",
            content=cdn_endpoint,
            record_type="CNAME"
        )
        
        if "error" not in record:
            self.managed_records[f"cdn-{operation_id}"] = record.get("id")
        
        return record


def get_dns_provider(name: str, **kwargs) -> DNSManager:
    """Factory function for DNS providers."""
    return DNSManager(provider=name, **kwargs)
