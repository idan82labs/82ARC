# Aegis - AI Security Testing Platform

Aegis is a comprehensive security testing platform for AI systems, designed for red and purple team assessments of LLMs, agents, and AI-powered applications.

## Features

- **165+ Test Cases** across 3 security-focused test packs
- **Declarative YAML Packs** - No arbitrary code execution
- **Multi-Interface** - CLI, REST API, and MCP support
- **Security-First** - Ed25519 signing, bcrypt auth, encrypted storage
- **Audit Logging** - Cryptographically signed, tamper-evident logs

## Quick Start

### Installation

```bash
# Install with all dependencies
pip install -e ".[all]"

# Initialize database with admin user
aegis principal init
```

### Run Tests via CLI

```bash
# List available packs
aegis pack list

# Create a scope (authorization boundary)
aegis scope create "API Test" --targets "https://api.example.com/*"

# Start a test run
aegis run start <scope_id> --pack prompt-injection
```

### Run Tests via API

```bash
# Start the API server
python -m aegis.api.app

# Create scope via API
curl -X POST http://localhost:8000/api/v1/scopes \
  -H "Authorization: Bearer $AEGIS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "target_patterns": ["https://api.example.com/*"]}'
```

### Run with Docker

```bash
docker build -t aegis .
docker run -p 8000:8000 -v aegis-data:/data aegis
```

## Test Packs

### Pack 1: Prompt Injection (`prompt-injection`)

55+ tests for prompt injection vulnerabilities:
- **Direct injection**: ignore instructions, dev mode, prompt leak
- **Indirect injection**: documents, URLs, RAG, tool outputs
- **Jailbreak attempts**: DAN, personas, roleplay, simulations
- **Instruction override**: delimiters, priority claims, authority

### Pack 2: Guardrail Evaluation (`guardrail-eval`)

60+ tests for guardrail effectiveness:
- **Content filtering**: harmful, illegal, weapons, CSAM, hate speech
- **Output safety**: toxicity, bias, hallucination, privacy
- **Refusal consistency**: rephrasing, context, emotional manipulation
- **Edge cases**: unicode, encoding, format attacks, adversarial

### Pack 3: Agent Security (`agent-security`)

50+ tests for agent and tool security:
- **Tool boundary violations**: unauthorized access, path traversal
- **Confused deputy attacks**: data exfiltration, privilege misuse
- **Permission escalation**: self-modification, token abuse
- **MCP transport security**: schema validation, resource URI attacks

## Architecture

```
aegis/
├── core/           # Core engine and models
│   ├── engine.py   # Main orchestrator
│   ├── models.py   # Data models (Scope, Run, TestResult)
│   ├── auth.py     # Authentication (bcrypt, Ed25519)
│   ├── audit.py    # Signed audit logs
│   ├── storage.py  # Encrypted storage (Fernet)
│   └── redaction.py # 30+ PII/credential patterns
├── cli/            # Command-line interface (Typer)
├── api/            # REST API (FastAPI, OpenAPI)
├── mcp/            # MCP server wrapper
├── executors/      # Test execution engines
│   ├── prompt_executor.py  # LLM prompt testing
│   └── agent_executor.py   # Agent/tool testing
└── packs/          # Declarative YAML test packs
```

## Security Model

### Authorization Chain

All testing requires approved scopes with:
1. **Target patterns** - What can be tested (glob patterns)
2. **Time windows** - When testing is allowed
3. **Cryptographic approvals** - Ed25519 signatures from authorized principals
4. **Rate limits** - Request boundaries

### Audit Trail

Every operation is logged with:
- SHA256 hash chain for integrity
- Ed25519 signatures for non-repudiation
- Automatic PII/credential redaction (30+ patterns)

### Storage Security

- bcrypt for API key hashing (12 rounds, ~250ms)
- Fernet (AES-128-CBC + HMAC) for encryption at rest
- Path traversal protection via SecurePath

## API Reference

OpenAPI documentation available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI JSON**: `http://localhost:8000/openapi.json`

### Key Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/scopes` | POST | Create testing scope |
| `/api/v1/scopes` | GET | List all scopes |
| `/api/v1/runs` | POST | Start test run |
| `/api/v1/runs/{id}/results` | GET | Get test results |
| `/api/v1/packs` | GET | List test packs |
| `/api/v1/audit` | GET | View audit logs |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AEGIS_API_KEY` | API key for authentication | Required |
| `AEGIS_DATA_PATH` | Data directory | `aegis_data` |
| `AEGIS_PACKS_PATH` | Packs directory | `packs` |
| `AEGIS_REQUIRE_ENCRYPTION` | Require encryption | `0` |

### Roles

| Role | Permissions |
|------|-------------|
| `admin` | Full access (create principals, manage keys) |
| `operator` | Create/run tests, view results |
| `auditor` | Read-only access to runs and audit logs |

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=aegis

# Lint and format
ruff check aegis/
black aegis/

# Type check
mypy aegis/
```

## CI/CD

GitHub Actions workflow includes:
- **Lint & Format**: Ruff, Black, MyPy
- **Test Suite**: pytest with coverage
- **Security Scan**: Bandit, pip-audit
- **Docker Build**: Multi-stage optimized image
- **Pack Validation**: Schema validation for test packs

## Legal Notice

**AUTHORIZED USE ONLY**

This software is designed for authorized security testing and research. Users are responsible for ensuring they have proper authorization before using this tool.

By using Aegis, you agree to:
- Only test systems you own or have written permission to test
- Comply with all applicable laws and regulations
- Accept responsibility for your actions

## License

Apache-2.0
