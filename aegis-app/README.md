# Aegis - AI Agent Security Testing Platform

A Next.js 14 application for AI agent security testing and assessment. Provides 54 security testing tools via MCP (Model Context Protocol) integration with credit-based billing and tiered access.

## Features

- **Marketing Site**: Full marketing pages (Home, Product, Methodology, Solutions, Pricing, Contact)
- **Authentication**: Clerk-based user authentication
- **Dashboard**: User dashboard with credit management, API keys, usage analytics, and billing
- **Admin Dashboard**: Real-time platform statistics and user management
- **API Integration**: RESTful API routes for keys, credits, usage tracking
- **Payment Processing**: Stripe integration for credit purchases
- **Database**: Supabase PostgreSQL with RLS policies
- **MCP Proxy**: Aegis MCP integration for AI security scanning (54 tools)

## Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Animation**: Framer Motion
- **Icons**: Lucide React
- **Authentication**: Clerk
- **Database**: Supabase PostgreSQL
- **Payments**: Stripe

## Getting Started

### Prerequisites

- Node.js 18+ and npm/yarn
- Clerk account (for authentication)
- Supabase account (for database)
- Stripe account (for payments)
- Aegis MCP server running (for security tools)

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   npm install
   ```

3. Copy `.env.example` to `.env.local` and fill in your credentials:
   ```bash
   cp .env.example .env.local
   ```

4. Set up your Supabase database using the schema file:
   ```bash
   # Apply the schema from aegis/supabase/schema.sql
   psql -U postgres -d aegis -f aegis/supabase/schema.sql
   ```

5. Run the development server:
   ```bash
   npm run dev
   ```

6. Open [http://localhost:3000](http://localhost:3000)

## Database Schema

The application uses the following tables (see `aegis/supabase/schema.sql` for full details):

### Core Tables

| Table | Description |
|-------|-------------|
| `users` | User records linked to Clerk via `clerk_id` |
| `credits` | User credit balances and tier info (auto-created on user signup) |
| `api_keys` | User API keys (hashed, with prefix for identification) |
| `usage` | Tool usage logs with `tool_name` and credits used |
| `transactions` | Credit purchase/refund history |
| `scans` | Security scan records with status and results |

### Admin Tables

| Table | Description |
|-------|-------------|
| `admin_users` | Admin role assignments |
| `system_health_logs` | Service health metrics |
| `admin_alerts` | System alerts and notifications |
| `daily_stats` | Aggregated daily statistics |

### Key Schema Notes

- `users.clerk_id` - Links to Clerk authentication (NOT `clerk_user_id`)
- `credits.balance` - Default 500 free credits on signup
- `credits.tier` - `'free'`, `'pro'`, or `'enterprise'`
- `usage.tool_name` - Name of the MCP tool used (NOT `operation`)
- `scans.scan_type` - Type of security scan (NOT `agent_name`)
- `scans.results` - JSON results (NOT `findings`)

## Project Structure

```
aegis-app/
├── app/                      # Next.js App Router
│   ├── api/                  # API routes
│   │   ├── admin/            # Admin statistics
│   │   ├── credits/          # Credit management
│   │   ├── keys/             # API key CRUD
│   │   ├── mcp/              # MCP proxy with credit deduction
│   │   ├── usage/            # Usage tracking
│   │   └── webhooks/         # Clerk & Stripe webhooks
│   ├── dashboard/            # Dashboard pages
│   │   ├── admin/            # Admin dashboard
│   │   ├── api-keys/
│   │   ├── billing/
│   │   ├── playground/       # Tool testing UI
│   │   ├── scans/
│   │   └── usage/
│   ├── contact/              # Contact page
│   ├── methodology/          # Methodology page
│   ├── pricing/              # Pricing page
│   ├── product/              # Product page
│   ├── sign-in/              # Clerk sign-in
│   ├── sign-up/              # Clerk sign-up
│   ├── solutions/            # Solutions page
│   ├── globals.css           # Global styles
│   ├── layout.tsx            # Root layout
│   └── page.tsx              # Home page
├── components/               # React components
│   ├── dashboard/            # Dashboard components
│   ├── home/                 # Home page components
│   ├── layout/               # Layout components (Nav, Footer)
│   └── ui/                   # UI components (Badge, Button, Toast)
├── lib/                      # Utilities
│   ├── credits.ts            # Credit cost definitions (54 tools)
│   ├── stripe.ts             # Stripe integration
│   └── supabase.ts           # Supabase client & typed functions
├── middleware.ts             # Clerk auth middleware
├── next.config.js
├── package.json
├── tailwind.config.js
└── tsconfig.json
```

## API Routes

### Authentication Required

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/credits` | Get user credit balance and tier |
| POST | `/api/credits` | Create Stripe checkout session |
| GET | `/api/keys` | List API keys |
| POST | `/api/keys` | Create new API key |
| DELETE | `/api/keys?id=<key_id>` | Delete API key |
| GET | `/api/usage` | Get usage history |
| POST | `/api/mcp/[...path]` | Proxy to Aegis MCP (deducts credits) |

### Admin Routes (Requires Admin Role)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/stats` | Get platform statistics |
| POST | `/api/admin/stats` | Execute admin actions |

### Webhooks (No Auth - Signature Verified)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/webhooks/clerk` | Clerk user events (creates users) |
| POST | `/api/webhooks/stripe` | Stripe payment events (adds credits) |

## Credit System

### Pricing Tiers

| Tier | Free Credits | Monthly Refill | Tool Access |
|------|--------------|----------------|-------------|
| Free | 500 | 0 | 8 basic tools |
| Pro | 0 | Varies by plan | 42 tools |
| Enterprise | 0 | Unlimited | All 54 tools |

### Credit Packages

| Package | Credits | Bonus | Price |
|---------|---------|-------|-------|
| Starter | 1,000 | 0 | $99 |
| Professional | 5,000 | +500 | $449 |
| Enterprise | 10,000 | +1,500 | $849 |

### Tool Categories & Credit Costs

| Category | Tools | Credit Range |
|----------|-------|--------------|
| AI Attack Core | 10 | 25-150 credits |
| AI Attack Enhanced | 4 | 75-100 credits |
| Agent Attacks | 11 | 50-200 credits |
| Reconnaissance | 4 | 25-200 credits |
| Vulnerability Scanning | 5 | 25-150 credits |
| Payload Generation | 5 | 25-100 credits |
| Infrastructure | 5 | 25-100 credits |
| Execution | 3 | 75-150 credits |
| Operations | 4 | 10-100 credits |
| Utilities | 2 | 5-10 credits |

See `lib/credits.ts` for complete credit cost definitions.

## Environment Variables

Required environment variables:

```bash
# Clerk Authentication
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=
CLERK_SECRET_KEY=
CLERK_WEBHOOK_SECRET=

# Supabase
NEXT_PUBLIC_SUPABASE_URL=
NEXT_PUBLIC_SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=

# Stripe
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=
NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=

# Aegis MCP Server
AEGIS_MCP_URL=http://localhost:8080
AEGIS_MCP_API_KEY=

# Admin (optional)
ADMIN_API_KEY=
USE_REAL_ADMIN_DATA=true
```

## Deployment

### Vercel (Recommended)

1. Push your code to GitHub
2. Import your repository in Vercel
3. Add all environment variables
4. Deploy

### Docker

```bash
docker build -t aegis-app .
docker run -p 3000:3000 --env-file .env.local aegis-app
```

## MCP Server Integration

The website proxies requests to the Aegis MCP server which provides 54 security testing tools:

- **AI Fingerprinting**: Identify AI models and their vulnerabilities
- **Jailbreak Testing**: Test AI guardrails with adaptive attacks
- **Prompt Injection**: Generate and test injection payloads
- **Agent Attacks**: Test agentic AI systems
- **RAG Poisoning**: Test retrieval-augmented generation security
- **Vulnerability Scanning**: SQL injection, XSS, SSRF detection
- **Payload Generation**: Create security testing payloads
- **Infrastructure**: Manage testing infrastructure

See `aegis/server.py` for complete tool definitions.

## License

MIT
