"""
NIGHTOWL Infrastructure Automation Module

Ephemeral C2 infrastructure: deploy, use, burn.

Components:
- providers.py: Cloud provider abstractions (DO, Linode, Vultr, AWS)
- manager.py: Infrastructure lifecycle management
- dns.py: DNS record management (Cloudflare, Route53, Namecheap)

Usage:
    from modules.infra import OperationOrchestrator
    
    orch = OperationOrchestrator(provider="digitalocean")
    result = orch.full_deploy(
        operation_id="op001",
        c2_type="sliver",
        redirector_count=2,
        ssh_key_path="/path/to/key"
    )
    
    # When done
    orch.teardown("op001")
"""

from .providers import (
    CloudProvider,
    DigitalOceanProvider,
    LinodeProvider,
    VultrProvider,
    AWSLightsailProvider,
    get_provider
)

from .manager import (
    InfrastructureManager,
    C2Configurator,
    OperationOrchestrator
)

from .dns import (
    CloudflareDNS,
    Route53DNS,
    NamecheapDNS,
    DNSManager,
    get_dns_provider
)

__all__ = [
    # Providers
    "CloudProvider",
    "DigitalOceanProvider", 
    "LinodeProvider",
    "VultrProvider",
    "AWSLightsailProvider",
    "get_provider",
    # Management
    "InfrastructureManager",
    "C2Configurator", 
    "OperationOrchestrator",
    # DNS
    "CloudflareDNS",
    "Route53DNS",
    "NamecheapDNS",
    "DNSManager",
    "get_dns_provider"
]
