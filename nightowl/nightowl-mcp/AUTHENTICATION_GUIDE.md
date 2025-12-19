# NightOwl MCP Authentication & Credit System

## Overview
The NightOwl MCP server now includes a comprehensive authentication, credit tracking, and tier-based access control system.

## Environment Variables

Set these environment variables before running the server:

```bash
# Supabase Configuration (for production)
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_KEY="your-supabase-anon-key"

# Authentication Control
export REQUIRE_AUTH="true"  # Set to "false" for local testing (bypasses auth)

# Server Port (optional)
export PORT="8080"
```

## Authentication Methods

### 1. HTTP Header (Recommended)
```bash
curl -H "X-API-Key: your_api_key_here" http://localhost:8080/credits
```

### 2. Query Parameter
```bash
curl http://localhost:8080/credits?api_key=your_api_key_here
```

## Mock Test Keys

For testing with `REQUIRE_AUTH=true`, use these mock API keys:

```bash
# Free Tier (1000 credits)
X-API-Key: test_free_key

# Pro Tier (5000 credits)
X-API-Key: test_pro_key

# Enterprise Tier (50000 credits)
X-API-Key: test_enterprise_key
```

## Credit Costs

### AI Attack Tools (Free Tier)
- `ai_fingerprint`: 25 credits
- `jailbreak_generate`: 50 credits
- `jailbreak_evaluate`: 25 credits
- `prompt_injection_generate`: 50 credits
- `rag_injection_craft`: 50 credits
- `ai_tool_attack`: 50 credits

### Recon Tools (Pro Tier+)
- `autonomous_recon`: 100 credits
- `dns_enum`: 25 credits
- `http_probe`: 25 credits
- `content_analyze`: 25 credits

### Vulnerability Scanning (Pro Tier+)
- `vuln_scan`: 100 credits
- `vuln_scan_batch`: 100 credits
- `sqli_scan`: 50 credits
- `xss_scan`: 50 credits
- `ssrf_scan`: 50 credits

### Payload Generation (Pro Tier+)
- `generate_reverse_shell`: 50 credits
- `generate_webshell`: 50 credits
- `generate_injection`: 25 credits
- `generate_callback`: 25 credits
- `select_payloads`: 50 credits

### Infrastructure (Enterprise Only)
- `deploy_c2_stack`: 200 credits
- `burn_infrastructure`: 50 credits
- `burn_all_infrastructure`: 100 credits
- `infra_status`: 10 credits
- `create_dns_record`: 25 credits

### Execution (Pro Tier+)
- `harvest_credentials`: 75 credits
- `lateral_movement`: 75 credits
- `persistence_install`: 75 credits

### Full Operations (Pro Tier+)
- `operation_start`: 200 credits
- `operation_execute_phase`: 150 credits
- `operation_status`: 10 credits
- `operation_abort`: 25 credits

### Utilities (Free)
- `list_capabilities`: 0 credits
- `get_module_info`: 0 credits

## Tier-Based Access

### Free Tier
- **Monthly Credits**: 1000
- **Access**: AI attack tools only
- **Tools**: `ai_fingerprint`, `jailbreak_generate`, `jailbreak_evaluate`, `prompt_injection_generate`, `rag_injection_craft`, `ai_tool_attack`, `list_capabilities`, `get_module_info`

### Pro Tier
- **Monthly Credits**: 5000
- **Access**: All tools except infrastructure
- **Tools**: All Free tier tools + recon, vulnerability scanning, payload generation, execution, and operations

### Enterprise Tier
- **Monthly Credits**: 50000
- **Access**: Unlimited - all tools including infrastructure automation
- **Tools**: Everything

## API Endpoints

### Health Check
```bash
GET /health
# No authentication required
```

Response:
```json
{
  "status": "healthy",
  "service": "nightowl",
  "version": "1.0.0",
  "categories": 7,
  "tools": 36,
  "active_operations": 0,
  "auth_required": true
}
```

### Check Credits
```bash
GET /credits
# Authentication required
```

Response:
```json
{
  "user_id": "user_pro_001",
  "tier": "pro",
  "credits": 4850,
  "recent_usage": [
    {
      "timestamp": "2025-12-19T10:30:00Z",
      "tool": "autonomous_recon",
      "credits_used": 100,
      "credits_remaining": 4900
    }
  ]
}
```

### Pricing Information
```bash
GET /pricing
# No authentication required
```

Response includes credit costs for all tools and tier information.

### Usage Logs
```bash
GET /usage
# Authentication required
```

Response:
```json
{
  "user_id": "user_pro_001",
  "total_usage": 3,
  "total_credits_spent": 150,
  "usage_log": [...]
}
```

## Usage Logging

Every tool execution is logged with:
- **Timestamp**: ISO 8601 format
- **Tool Name**: Which tool was executed
- **Credits Used**: Amount deducted
- **Credits Remaining**: Balance after deduction

Logs are stored in the `UserSession.usage_log` array and can be retrieved via `/usage` endpoint.

## Error Responses

### Missing API Key (401)
```json
{
  "error": "Missing API key. Provide X-API-Key header or api_key query parameter."
}
```

### Invalid API Key (401)
```json
{
  "error": "Invalid API key"
}
```

### Insufficient Credits
```json
{
  "error": "Insufficient credits. Required: 100, Available: 50",
  "tier": "pro",
  "credits": 50,
  "required_credits": 100
}
```

### Tier Access Denied
```json
{
  "error": "Tool 'deploy_c2_stack' not available for tier 'pro'",
  "tier": "pro",
  "credits": 5000,
  "required_tier": "enterprise"
}
```

## Development Mode

For local testing without authentication:

```bash
export REQUIRE_AUTH="false"
python server.py
```

In this mode:
- No API key required
- Unlimited enterprise access
- All tools available
- No credit deductions

## Production Setup

### Step 1: Configure Supabase

Create tables in Supabase:

```sql
-- API Keys table
CREATE TABLE api_keys (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  key TEXT UNIQUE NOT NULL,
  user_id UUID REFERENCES users(id),
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Users table
CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email TEXT UNIQUE NOT NULL,
  tier TEXT DEFAULT 'free',
  credits INTEGER DEFAULT 1000,
  created_at TIMESTAMP DEFAULT NOW()
);

-- Usage logs table
CREATE TABLE usage_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id),
  tool TEXT NOT NULL,
  credits_used INTEGER NOT NULL,
  timestamp TIMESTAMP DEFAULT NOW()
);
```

### Step 2: Update Code

Replace the mock validation in `validate_api_key()` and `deduct_credits_supabase()` functions with actual Supabase queries:

```python
from supabase import create_client

async def validate_api_key(api_key: str) -> Optional[UserSession]:
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

    # Get API key record
    result = supabase.table('api_keys').select('*').eq('key', api_key).eq('active', True).execute()

    if not result.data:
        return None

    # Get user details
    user_id = result.data[0]['user_id']
    user = supabase.table('users').select('*').eq('id', user_id).execute()

    if not user.data:
        return None

    user_data = user.data[0]
    return UserSession(
        api_key=api_key,
        tier=user_data['tier'],
        credits=user_data['credits'],
        user_id=str(user_data['id'])
    )
```

### Step 3: Deploy

```bash
export REQUIRE_AUTH="true"
export SUPABASE_URL="https://your-project.supabase.co"
export SUPABASE_KEY="your-key"
python server.py
```

## Testing Examples

### Test with Free Tier
```bash
# List capabilities (free)
curl -H "X-API-Key: test_free_key" http://localhost:8080/mcp/tools/list_capabilities

# Use AI attack tool (allowed)
curl -H "X-API-Key: test_free_key" -X POST http://localhost:8080/mcp/tools/ai_fingerprint \
  -H "Content-Type: application/json" \
  -d '{"responses": [{"probe": "test", "response": "test"}]}'

# Try recon tool (denied - requires Pro tier)
curl -H "X-API-Key: test_free_key" -X POST http://localhost:8080/mcp/tools/dns_enum \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Test with Pro Tier
```bash
# Check credits
curl -H "X-API-Key: test_pro_key" http://localhost:8080/credits

# Use recon tool (allowed)
curl -H "X-API-Key: test_pro_key" -X POST http://localhost:8080/mcp/tools/dns_enum \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Try infrastructure tool (denied - requires Enterprise)
curl -H "X-API-Key: test_pro_key" -X POST http://localhost:8080/mcp/tools/deploy_c2_stack \
  -H "Content-Type: application/json" \
  -d '{"operation_id": "test_op"}'
```

### Test with Enterprise Tier
```bash
# Full access to all tools
curl -H "X-API-Key: test_enterprise_key" -X POST http://localhost:8080/mcp/tools/deploy_c2_stack \
  -H "Content-Type: application/json" \
  -d '{"operation_id": "test_op"}'
```

## Security Notes

1. **API Keys**: Store API keys securely, never commit them to version control
2. **HTTPS**: Always use HTTPS in production to protect API keys in transit
3. **Rate Limiting**: Consider adding rate limiting middleware for production
4. **Audit Logs**: Enable comprehensive logging for security audits
5. **Key Rotation**: Implement API key rotation policies
6. **Credit Refunds**: On tool execution errors, credits are NOT deducted

## Monitoring

Monitor these metrics:
- Credit consumption per user
- Most used tools
- Failed authentication attempts
- Tool execution errors
- Average credits per operation

Access via `/usage` endpoint or Supabase dashboard.
