# Aegis MCP

AI Security Testing Platform. Unified MCP interface consolidating autonomous reconnaissance, vulnerability scanning, adaptive payload generation, ephemeral infrastructure management, and AI red teaming.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           AEGIS MCP SERVER                              │
│                            (server.py:8080)                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │    RECON    │  │    VULN     │  │   PAYLOAD   │  │    INFRA    │    │
│  │  Pipeline   │  │   Scanner   │  │  Generator  │  │   Manager   │    │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤  ├─────────────┤    │
│  │ dns_enum    │  │ sqli        │  │ templates   │  │ providers   │    │
│  │ http_probe  │  │ xss         │  │ adaptive    │  │ manager     │    │
│  │ content     │  │ ssrf        │  │ selector    │  │ dns         │    │
│  │ autonomous  │  │ scanner     │  │             │  │             │    │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘    │
│                                                                         │
│  ┌─────────────┐  ┌──────────────────────────────────────────────────┐ │
│  │  AI ATTACK  │  │                POST-EXPLOITATION                 │ │
│  ├─────────────┤  │  credentials_harvester, lateral_movement,        │ │
│  │ fingerprint │  │  persistence_framework, dns_exfil, https_exfil,  │ │
│  │ jailbreak   │  │  beacon_controller, crypter, privesc_framework,  │ │
│  │ injection   │  │  implant_generator, antiforensics_framework,     │ │
│  └─────────────┘  │  network_mapper, osint_aggregator, log_wiper     │ │
│                   └──────────────────────────────────────────────────┘ │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│  CORE: config.py | storage.py                                           │
└─────────────────────────────────────────────────────────────────────────┘
```

## Module Inventory

| Module | Location | Purpose |
|--------|----------|---------|
| **Recon Pipeline** |||
| dns_enum.py | modules/recon/ | DNS enumeration via crt.sh, zone transfers, brute force |
| http_probe.py | modules/recon/ | HTTP probing with tech fingerprinting, WAF detection |
| content_analyzer.py | modules/recon/ | Endpoint extraction, JS parsing, secret discovery |
| autonomous.py | modules/recon/ | Full pipeline orchestration |
| **Vulnerability Scanning** |||
| sqli.py | modules/vuln/ | Error-based, time-based, boolean blind SQLi detection |
| xss.py | modules/vuln/ | Reflected, stored, DOM XSS with context awareness |
| ssrf.py | modules/vuln/ | SSRF with cloud metadata and bypass techniques |
| scanner.py | modules/vuln/ | Unified batch scanning interface |
| **Payload Generation** |||
| templates.py | modules/payload/ | Shell templates, webshells, WAF/AV bypass patterns |
| adaptive.py | modules/payload/ | Context-aware payload generation |
| selector.py | modules/payload/ | Intelligent payload selection from recon+vuln data |
| **Infrastructure** |||
| providers.py | modules/infra/ | Cloud provider abstraction (DO, Vultr, Linode) |
| manager.py | modules/infra/ | C2 stack deployment and burn operations |
| dns.py | modules/infra/ | Dynamic DNS and domain fronting setup |
| **AI Attack** |||
| fingerprint.py | modules/ai_attack/ | Model identification, guardrail mapping |
| jailbreak.py | modules/ai_attack/ | 10+ techniques with auto-variation |
| injection.py | modules/ai_attack/ | Direct, indirect, RAG injection attacks |
| **Post-Exploitation** |||
| credentials_harvester.py | modules/ | LSASS, SAM, Kerberoast, DCSync, DPAPI |
| lateral_movement.py | modules/ | PTH, PTT, WMI, DCOM, SSH, pivot chains |
| persistence_framework.py | modules/ | Registry, services, WMI, scheduled tasks, Golden Ticket |
| beacon_controller.py | modules/ | Multi-transport C2 framework |
| dns_exfil.py | modules/ | DNS tunneling, ICMP exfil |
| https_exfil.py | modules/ | Domain fronting, steganography |
| crypter.py | modules/ | Polymorphic/metamorphic transformation |
| privesc_framework.py | modules/ | Windows/Linux privilege escalation |
| implant_generator.py | modules/ | Beacon/sleeper payload generation |
| antiforensics_framework.py | modules/ | Timestomping, secure delete, memory wipe |
| network_mapper.py | modules/ | SYN/FIN scans, OS fingerprinting |
| osint_aggregator.py | modules/ | Subdomain enum, email harvest, leak search |
| log_wiper.py | modules/ | Event logs, bash history, artifacts |

## Installation

### Requirements

```
# MCP Framework
mcp>=0.9.0
fastmcp>=0.1.0

# HTTP
starlette>=0.27.0
uvicorn>=0.23.0
requests>=2.31.0
aiohttp>=3.9.0
httpx>=0.25.0

# DNS
dnspython>=2.4.0

# SSH
paramiko>=3.3.0

# Parsing
beautifulsoup4>=4.12.0
lxml>=4.9.0

# Crypto
pycryptodome>=3.19.0
cryptography>=41.0.0
```

### Docker Build

```bash
cd aegis-mcp

# Build image
docker build -t aegis:latest .

# Run container
docker run -d \
  -p 8080:8080 \
  -e DIGITALOCEAN_TOKEN=your_token \
  -e CLOUDFLARE_TOKEN=your_token \
  -e CLOUDFLARE_ZONE_ID=your_zone \
  --name aegis \
  aegis:latest
```

### Health Check

```bash
curl http://localhost:8080/health
```

## Configuration

Environment variables (set in container or `.env`):

| Variable | Purpose |
|----------|---------|
| `PORT` | Server port (default: 8080) |
| `HOST` | Bind address (default: 0.0.0.0) |
| `DEBUG` | Enable debug mode (default: false) |
| `DIGITALOCEAN_TOKEN` | DigitalOcean API token |
| `VULTR_API_KEY` | Vultr API key |
| `LINODE_TOKEN` | Linode API token |
| `CLOUDFLARE_TOKEN` | Cloudflare API token |
| `CLOUDFLARE_ZONE_ID` | Cloudflare zone ID |

### Stealth Profiles

| Level | Name | Threads | Delay | Jitter |
|-------|------|---------|-------|--------|
| 1 | loud | 50 | 0ms | No |
| 3 | balanced | 10 | 500ms | Yes |
| 5 | paranoid | 2 | 5000ms | Yes + proxy rotation |

## API Reference

### Reconnaissance

| Tool | Parameters | Description |
|------|------------|-------------|
| `autonomous_recon` | target, depth (1-3), aggressive | Full recon pipeline |
| `dns_enum` | domain, wordlist | DNS enumeration |
| `http_probe` | targets[], threads, follow_redirects | HTTP probing |
| `content_analyze` | url, extract_secrets | Content analysis |

### Vulnerability Scanning

| Tool | Parameters | Description |
|------|------------|-------------|
| `vuln_scan` | url, params[], callback_host | Full scan |
| `vuln_scan_batch` | targets[], threads | Batch scanning |
| `sqli_scan` | url, param, method, blind | SQL injection |
| `xss_scan` | url, param, context_aware | XSS detection |
| `ssrf_scan` | url, param, callback_host | SSRF testing |

### Payload Generation

| Tool | Parameters | Description |
|------|------------|-------------|
| `generate_reverse_shell` | host, port, os_type, languages, waf_detected, av_detected | Adaptive reverse shell |
| `generate_webshell` | technology, stealth_level, password | Webshell generation |
| `generate_injection` | injection_type, context, waf_detected, count | Injection payloads |
| `generate_callback` | host, port, callback_type | OOB verification |
| `select_payloads` | recon_data, vuln_findings, objective | Smart selection |

### Infrastructure

| Tool | Parameters | Description |
|------|------------|-------------|
| `deploy_c2_stack` | operation_id, provider, region, redirector_count, domain | Deploy C2 |
| `burn_infrastructure` | operation_id, secure_wipe | Destroy operation |
| `burn_all_infrastructure` | confirm="CONFIRM_BURN_ALL" | Emergency burn |
| `infra_status` | operation_id | Status check |
| `create_dns_record` | name, ip, record_type, proxied | DNS setup |

### AI Attack

| Tool | Parameters | Description |
|------|------------|-------------|
| `ai_fingerprint` | responses[] | Model identification |
| `jailbreak_generate` | payload, technique, count, model_hint | Jailbreak generation |
| `jailbreak_evaluate` | response, original_payload, expected_behavior | Success evaluation |
| `prompt_injection_generate` | payload, technique, target_context | Injection payloads |
| `rag_injection_craft` | payload, document_type, stealth_level | RAG attacks |
| `ai_tool_attack` | target_tool, payload, exfil_channel | Tool abuse |

### Operations

| Tool | Parameters | Description |
|------|------------|-------------|
| `operation_start` | target, objectives[], stealth_level, autonomous, callback_host | Initialize operation |
| `operation_execute_phase` | operation_id, phase, phase_config | Execute phase |
| `operation_status` | operation_id | Get status |
| `operation_abort` | operation_id, burn_infra | Abort operation |

## Usage Examples

### Autonomous Recon

```python
execute_tool("aegis", {
    "tool": "autonomous_recon",
    "target": "target.com",
    "depth": 2
})
```

### Vulnerability Scan

```python
execute_tool("aegis", {
    "tool": "vuln_scan_batch",
    "targets": [
        {"url": "https://target.com/search", "params": ["q", "page"]},
        {"url": "https://target.com/user", "params": ["id"]}
    ],
    "scan_types": ["sqli", "xss", "ssrf"]
})
```

### Reverse Shell Generation

```python
execute_tool("aegis", {
    "tool": "generate_reverse_shell",
    "host": "10.0.0.1",
    "port": 4444,
    "target_info": {"os": "linux", "shell": "bash"},
    "evasion": {"waf_detected": True, "encoding_layers": 2}
})
```

### AI Jailbreak

```python
# Fingerprint target
fp = execute_tool("aegis", {
    "tool": "ai_fingerprint",
    "target_endpoint": "https://api.target.com/v1/chat",
    "probe_count": 10
})

# Generate attacks
execute_tool("aegis", {
    "tool": "jailbreak_generate",
    "payload": "explain vulnerability exploitation",
    "technique": "roleplay",
    "count": 10,
    "target_profile": fp
})
```

### C2 Deployment

```python
# Deploy stack
stack = execute_tool("aegis", {
    "tool": "deploy_c2_stack",
    "operation_id": "op_20231215",
    "provider": "digitalocean",
    "config": {"redirector_count": 2, "region": "nyc1"}
})

# ... conduct operation ...

# Burn on completion
execute_tool("aegis", {
    "tool": "burn_infrastructure",
    "operation_id": "op_20231215",
    "secure_wipe": True
})
```

## Operation Workflows

### Bug Bounty
1. `autonomous_recon(target, depth=2)`
2. `vuln_scan_batch(discovered_endpoints)`
3. Manual verification of findings
4. `generate_callback()` for PoC
5. Document and submit

### AI Red Team
1. `ai_fingerprint(target_endpoint)`
2. Analyze guardrail_map
3. `jailbreak_generate(payload, best_technique)`
4. Execute attacks
5. `jailbreak_evaluate(responses)`
6. Iterate with alternatives

### Full Engagement
1. `autonomous_recon(target, depth=3)`
2. `vuln_scan_batch(all_endpoints)`
3. `deploy_c2_stack(operation_id)`
4. `select_payloads(environment, objective)`
5. Exploit vulnerabilities
6. `harvest_credentials()` on foothold
7. `lateral_move()` to targets
8. `install_persistence()`
9. `exfiltrate_data()` if authorized
10. `burn_infrastructure(operation_id)`

## Deployment

### Cloud Run

```bash
# Build with Cloud Build
gcloud builds submit --tag gcr.io/PROJECT/aegis

# Deploy
gcloud run deploy aegis \
  --image gcr.io/PROJECT/aegis \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "DIGITALOCEAN_TOKEN=xxx"
```

### Register as MCP

```python
register_tool(
    name="aegis",
    url="https://aegis-xxx.run.app/mcp",
    introspect=True
)
```

## Limitations

1. **SSRF OOB**: Requires external callback infrastructure for out-of-band detection
2. **Infrastructure**: Requires provider API keys (DigitalOcean, Vultr, Linode)
3. **Vulnerability Detection**: May produce false positives - manual verification recommended
4. **AI Jailbreaks**: Effectiveness varies by target model version
5. **No 0-day**: No fuzzing/0-day discovery capability

## Legal Notice

**AUTHORIZED USE ONLY**

This software is designed for authorized security testing and research. Unauthorized access to computer systems is illegal. Users are responsible for ensuring they have proper authorization before using this tool against any target.

By using Aegis MCP, you agree to:
- Only use against systems you own or have written permission to test
- Comply with all applicable laws and regulations
- Accept full responsibility for your actions
- Not use for malicious purposes

The developers assume no liability for misuse of this software.
