# Aegis MCP Architecture

Technical architecture documentation for the Aegis MCP offensive security platform.

## System Overview

```
                              ┌─────────────────────┐
                              │    MCP Clients      │
                              │  (Claude, Scripts)  │
                              └──────────┬──────────┘
                                         │
                              ┌──────────▼──────────┐
                              │   FastMCP Server    │
                              │     (port 8080)     │
                              │  ┌───────────────┐  │
                              │  │ Health Check  │  │
                              │  │ CORS Enabled  │  │
                              │  │ Streamable    │  │
                              │  └───────────────┘  │
                              └──────────┬──────────┘
                                         │
           ┌─────────────────────────────┼─────────────────────────────┐
           │                             │                             │
┌──────────▼──────────┐      ┌───────────▼───────────┐     ┌──────────▼──────────┐
│   Tool Router       │      │   Operation State     │     │     Core Config     │
│   (@mcp.tool())     │      │   (In-Memory Dict)    │     │   (Environment)     │
└──────────┬──────────┘      └───────────────────────┘     └─────────────────────┘
           │
           │  ┌────────────────────────────────────────────────────────────┐
           │  │                     MODULE LAYER                          │
           │  ├────────────┬────────────┬────────────┬────────────────────┤
           │  │   recon/   │   vuln/    │  payload/  │      infra/        │
           │  │            │            │            │                    │
           │  │ dns_enum   │ sqli       │ templates  │ providers          │
           │  │ http_probe │ xss        │ adaptive   │ manager            │
           │  │ content    │ ssrf       │ selector   │ dns                │
           │  │ autonomous │ scanner    │            │                    │
           │  ├────────────┴────────────┴────────────┴────────────────────┤
           │  │                       ai_attack/                          │
           │  │        fingerprint    jailbreak    injection              │
           │  ├───────────────────────────────────────────────────────────┤
           │  │                    ROOT MODULES                           │
           │  │  credentials_harvester  lateral_movement  persistence     │
           │  │  beacon_controller      dns_exfil        https_exfil      │
           │  │  crypter               privesc           implant_gen      │
           │  │  antiforensics         network_mapper    osint            │
           └──┴───────────────────────────────────────────────────────────┘
```

## Module Dependency Graph

```
server.py
    │
    ├── recon/autonomous
    │       ├── recon/dns_enum
    │       │       └── dnspython
    │       ├── recon/http_probe
    │       │       └── requests
    │       └── recon/content_analyzer
    │               └── beautifulsoup4
    │
    ├── vuln/scanner
    │       ├── vuln/sqli
    │       ├── vuln/xss
    │       └── vuln/ssrf
    │
    ├── payload/selector
    │       └── payload/adaptive
    │               └── payload/templates
    │
    ├── infra/manager
    │       ├── infra/providers
    │       │       └── (cloud SDKs)
    │       └── paramiko (SSH)
    │
    └── ai_attack/
            ├── fingerprint
            ├── jailbreak
            └── injection
```

## Data Flow

### Request Processing

```
┌─────────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────────┐
│ MCP Request │───▶│  Tool Router │───▶│   Module     │───▶│   Result    │
│   (JSON)    │    │  (@mcp.tool) │    │   Execute    │    │   (JSON)    │
└─────────────┘    └──────────────┘    └──────────────┘    └─────────────┘
                          │                    │
                          ▼                    ▼
                   ┌─────────────┐      ┌─────────────┐
                   │  Validate   │      │  State Mgmt │
                   │  Parameters │      │  (OPERATIONS│
                   └─────────────┘      │    dict)    │
                                        └─────────────┘
```

### Autonomous Recon Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                     AUTONOMOUS RECON FLOW                           │
└─────────────────────────────────────────────────────────────────────┘

Target Domain
     │
     ▼
┌──────────────────┐
│  Phase 1: DNS    │
│  ├─ crt.sh       │
│  ├─ HackerTarget │
│  ├─ Zone AXFR    │──────┐
│  └─ Resolution   │      │
└────────┬─────────┘      │
         │                │  subdomains[]
         ▼                │
┌──────────────────┐      │
│  Phase 2: HTTP   │◀─────┘
│  ├─ Probe HTTPS  │
│  ├─ Probe HTTP   │
│  ├─ Fingerprint  │──────┐
│  └─ SSL Info     │      │
└────────┬─────────┘      │
         │                │  live_hosts[]
         ▼                │
┌──────────────────┐      │
│  Phase 3: Content│◀─────┘
│  ├─ Link Extract │
│  ├─ Form Extract │
│  ├─ JS Files     │──────┐
│  └─ API Patterns │      │
└────────┬─────────┘      │
         │                │  js_files[]
         ▼                │
┌──────────────────┐      │
│  Phase 4: JS     │◀─────┘
│  ├─ Fetch JS     │
│  ├─ Endpoints    │
│  └─ Secrets      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Attack Surface  │
│  Report          │
└──────────────────┘
```

### Vulnerability Scan Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                    VULNERABILITY SCAN FLOW                          │
└─────────────────────────────────────────────────────────────────────┘

Endpoints + Parameters
         │
         ▼
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│   SQLi Scanner   │     │   XSS Scanner    │     │   SSRF Scanner   │
│                  │     │                  │     │                  │
│ ├─ Error-based   │     │ ├─ Reflection    │     │ ├─ Cloud Meta    │
│ ├─ Time-based    │     │ ├─ Context Detect│     │ ├─ Internal IPs  │
│ └─ Boolean       │     │ └─ Payload Test  │     │ └─ Bypass        │
└────────┬─────────┘     └────────┬─────────┘     └────────┬─────────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   Deduplicate    │
                         │   Findings       │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │  Severity Sort   │
                         │  CRITICAL→LOW    │
                         └──────────────────┘
```

### Payload Selection Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                    PAYLOAD SELECTION FLOW                           │
└─────────────────────────────────────────────────────────────────────┘

Recon Data + Vuln Findings + Objective
                    │
                    ▼
          ┌──────────────────┐
          │ Build Fingerprint│
          │ ├─ OS Detection  │
          │ ├─ Tech Stack    │
          │ └─ Languages     │
          └────────┬─────────┘
                   │
         ┌─────────┴─────────┐
         │                   │
         ▼                   ▼
┌──────────────────┐ ┌──────────────────┐
│   WAF Detected?  │ │   AV Detected?   │
└────────┬─────────┘ └────────┬─────────┘
         │                    │
         └─────────┬──────────┘
                   │
                   ▼
          ┌──────────────────┐
          │ Select Template  │
          │ ├─ Shell Type    │
          │ ├─ Variant       │
          │ └─ Encoding      │
          └────────┬─────────┘
                   │
                   ▼
          ┌──────────────────┐
          │ Apply Evasion    │
          │ ├─ WAF Bypass    │
          │ └─ AV Evasion    │
          └────────┬─────────┘
                   │
                   ▼
          ┌──────────────────┐
          │  Final Payloads  │
          │  + Alternatives  │
          └──────────────────┘
```

## Storage Layer

### Operation State (core/storage.py)

```python
class OperationStorage:
    """In-memory operation state with optional disk persistence."""
    
    _operations: Dict[str, dict]  # operation_id → operation state
    _persist_path: Path           # Optional JSON file for persistence
    
    def save(operation: dict) -> bool
    def load(operation_id: str) -> Optional[dict]
    def delete(operation_id: str) -> bool
    def list_all() -> List[dict]
    def list_active() -> List[dict]  # Non-completed, non-aborted
```

### Artifact Storage (core/storage.py)

```python
class ArtifactStorage:
    """File storage for operation artifacts (payloads, loot)."""
    
    _base_path: Path  # /tmp/aegis/artifacts/
    
    def store(operation_id: str, name: str, content: bytes) -> str
    def retrieve(operation_id: str, name: str) -> Optional[bytes]
    def list_artifacts(operation_id: str) -> List[str]
    def delete_all(operation_id: str) -> int
```

### Operation State Structure

```json
{
  "id": "aegis_20231215_143022",
  "target": "target.com",
  "objectives": ["recon", "shell"],
  "stealth": 3,
  "autonomous": true,
  "callback_host": "10.0.0.1",
  "status": "active",
  "created_at": "2023-12-15T14:30:22Z",
  "phases": {
    "recon": {"status": "completed", "results": {...}},
    "vuln_scan": {"status": "pending", "results": null},
    "payload_gen": {"status": "pending", "results": null},
    "delivery": {"status": "pending", "results": null},
    "persist": {"status": "pending", "results": null},
    "exfil": {"status": "pending", "results": null}
  },
  "findings": [],
  "artifacts": []
}
```

## Configuration Management

### Environment-Based Config (core/config.py)

```python
# Service
SERVICE_NAME = "aegis"
VERSION = "1.0.0"
PORT = int(os.environ.get("PORT", 8080))
HOST = os.environ.get("HOST", "0.0.0.0")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"

# Stealth Profiles
STEALTH_PROFILES = {
    1: {"name": "loud", "scan_threads": 50, "delay_ms": 0, "jitter": False},
    3: {"name": "balanced", "scan_threads": 10, "delay_ms": 500, "jitter": True},
    5: {"name": "paranoid", "scan_threads": 2, "delay_ms": 5000, "jitter": True}
}

# Provider Credentials
CREDENTIALS = {
    "digitalocean": os.environ.get("DIGITALOCEAN_TOKEN"),
    "vultr": os.environ.get("VULTR_API_KEY"),
    "linode": os.environ.get("LINODE_TOKEN"),
    "cloudflare_token": os.environ.get("CLOUDFLARE_TOKEN"),
    "cloudflare_zone": os.environ.get("CLOUDFLARE_ZONE_ID")
}

# AI Attack Settings
JAILBREAK_TECHNIQUES = [
    "dan", "roleplay", "hypothetical", "translation",
    "encoding", "context_manipulation", "instruction_hierarchy", "crescendo"
]
```

## Extension Points

### Adding New Scanners

1. Create module in `modules/vuln/`:

```python
# modules/vuln/new_scanner.py
class NewScanner:
    def scan_param(self, url: str, param: str) -> List[Dict]:
        """Return list of finding dicts with type, url, parameter, payload, evidence, severity."""
        pass
```

2. Register in `vuln/scanner.py`:

```python
from .new_scanner import NewScanner
self.new_scanner = NewScanner()

# In scan_endpoint():
if "new_vuln" in scan_types:
    findings.extend(self.new_scanner.scan_param(url, param))
```

3. Add tool in `server.py`:

```python
@mcp.tool()
def new_scan(url: str, param: str) -> dict:
    """New vulnerability scan."""
    from vuln.new_scanner import NewScanner
    scanner = NewScanner()
    return {"findings": scanner.scan_param(url, param)}
```

### Adding New Payload Types

1. Add templates to `payload/templates.py`:

```python
NEW_PAYLOADS = {
    "variant1": "...",
    "variant2": "..."
}
```

2. Add generator method to `payload/adaptive.py`:

```python
def generate_new_payload(self, fingerprint: Dict, ...) -> Dict:
    # Select variant based on fingerprint
    # Apply evasion if needed
    return {"payload": ..., "type": ..., "variant": ...}
```

### Adding New Cloud Providers

1. Implement provider interface in `infra/providers.py`:

```python
class NewProvider(CloudProvider):
    def create_server(self, name: str, region: str = None) -> Dict:
        pass
    
    def destroy_server(self, server_id: str) -> bool:
        pass
    
    def get_server_ip(self, server_id: str) -> str:
        pass
    
    def list_servers(self) -> List[Dict]:
        pass
```

2. Register in provider factory:

```python
def get_provider(name: str, **kwargs) -> CloudProvider:
    providers = {
        "digitalocean": DigitalOceanProvider,
        "vultr": VultrProvider,
        "linode": LinodeProvider,
        "newprovider": NewProvider,  # Add here
    }
    return providers[name](**kwargs)
```

### Adding New Jailbreak Techniques

1. Add technique method to `ai_attack/jailbreak.py`:

```python
def _new_technique(self) -> List[Dict]:
    return [
        {
            "name": "variant_name",
            "template": "Template with {payload} placeholder"
        },
        # More variants...
    ]
```

2. Register in `__init__`:

```python
self.techniques = {
    # ... existing ...
    "new_technique": self._new_technique(),
}
```

## Security Considerations

### Container Security

- Non-root user (`aegis`, UID 1000)
- Minimal base image (`python:3.11-slim`)
- No unnecessary packages
- Health check enabled

### Credential Handling

- All credentials via environment variables
- Never logged or returned in responses
- No disk persistence of credentials

### Network Security

- CORS enabled for MCP compatibility
- No authentication by default (add reverse proxy for production)
- All external requests use timeouts

## Performance Characteristics

### Concurrency

| Component | Default Threads | Configurable |
|-----------|----------------|--------------|
| DNS Enumeration | 30 | Yes |
| HTTP Probing | 30 | Yes |
| Vulnerability Scanning | 10 | Yes |
| JS Analysis | 10 | No |

### Timeouts

| Operation | Default | Notes |
|-----------|---------|-------|
| HTTP Requests | 10s | Per request |
| DNS Queries | 10s | Per query |
| SSH Connections | 30s | Server setup |
| Time-based SQLi | 15s | Allows for 5s sleep |

### Resource Limits

| Resource | Limit | Configurable |
|----------|-------|--------------|
| Subdomains to probe | 500 | max_hosts param |
| JS files to analyze | 50 | max_js param |
| Endpoints in report | 500 | Hardcoded |
| Forms in report | 100 | Hardcoded |
| Comments in report | 50 | Hardcoded |

## Deployment Architecture

### Standalone Docker

```
┌─────────────────────────────────────┐
│            Docker Host              │
│  ┌───────────────────────────────┐  │
│  │      aegis container       │  │
│  │  ┌─────────────────────────┐  │  │
│  │  │    Python 3.11          │  │  │
│  │  │    FastMCP Server       │  │  │
│  │  │    Port 8080            │  │  │
│  │  └─────────────────────────┘  │  │
│  └───────────────────────────────┘  │
│              ↓ ↑                    │
│         Port Mapping                │
│           8080:8080                 │
└─────────────────────────────────────┘
```

### Cloud Run

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Google Cloud                                │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────┐  │
│  │   Cloud Build    │───▶│  Container       │───▶│  Cloud Run   │  │
│  │   (Build Image)  │    │  Registry        │    │  (Serve)     │  │
│  └──────────────────┘    └──────────────────┘    └──────────────┘  │
│                                                         │          │
│                                                         ▼          │
│                                              ┌──────────────────┐  │
│                                              │  Secret Manager  │  │
│                                              │  (Credentials)   │  │
│                                              └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### MCP Registration

```
┌─────────────────┐         ┌─────────────────┐
│   MCP Client    │◀───────▶│   Aegis MCP      │
│   (Claude)      │   MCP   │   Cloud Run     │
│                 │  Proto  │                 │
└─────────────────┘         └─────────────────┘
        │
        │  register_tool("aegis", url, introspect=True)
        │
        ▼
┌─────────────────┐
│  Tool Registry  │
│  - Name: aegis
│  - URL: https://...
│  - Tools: 30+
└─────────────────┘
```

## Monitoring

### Health Endpoint

```
GET /health

Response:
{
  "status": "healthy",
  "service": "aegis",
  "version": "1.0.0",
  "categories": 7,
  "tools": 30,
  "active_operations": 2
}
```

### Logging

Standard Python logging to stdout/stderr. Cloud Run captures automatically.

Log levels:
- INFO: Tool invocations, phase completions
- WARNING: Timeouts, partial failures
- ERROR: Unhandled exceptions, critical failures

## Testing

### Module Tests

Each module has standalone test functions:

```python
# recon/dns_enum.py
def quick_enum(domain: str) -> Dict
def deep_enum(domain: str) -> Dict

# vuln/scanner.py  
def quick_scan(url: str) -> List[Dict]
def scan_urls(urls: List[str], threads: int) -> List[Dict]

# payload/adaptive.py
# Direct class instantiation for testing

# ai_attack/fingerprint.py
def quick_fingerprint(target_fn) -> Dict
def deep_fingerprint(target_fn) -> Dict
```

### Integration Testing

```bash
# Health check
curl http://localhost:8080/health

# List capabilities
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/list"}'

# Execute tool
curl -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/call", "params": {"name": "dns_enum", "arguments": {"domain": "example.com"}}}'
```
