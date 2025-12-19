# Aegis - AI Agent Security Testing Platform

A Next.js 14 application for AI agent security testing and assessment, converted from a single-file React application to a full-featured App Router structure.

## Features

- **Marketing Site**: Full marketing pages (Home, Product, Methodology, Solutions, Pricing, Contact)
- **Authentication**: Clerk-based user authentication
- **Dashboard**: User dashboard with credit management, API keys, usage analytics, and billing
- **API Integration**: RESTful API routes for keys, credits, usage tracking
- **Payment Processing**: Stripe integration for credit purchases
- **Database**: Supabase for user data and usage tracking
- **MCP Proxy**: NightOwl MCP integration for AI security scanning

## Tech Stack

- **Framework**: Next.js 14 (App Router)
- **Language**: TypeScript
- **Styling**: Tailwind CSS
- **Animation**: Framer Motion
- **Icons**: Lucide React
- **Authentication**: Clerk
- **Database**: Supabase
- **Payments**: Stripe

## Getting Started

### Prerequisites

- Node.js 18+ and npm/yarn
- Clerk account (for authentication)
- Supabase account (for database)
- Stripe account (for payments)

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

4. Set up your Supabase database with the following tables:
   - `users` (id, clerk_user_id, email, credits, created_at, updated_at)
   - `api_keys` (id, user_id, clerk_user_id, name, key_hash, created_at, last_used_at)
   - `usage` (id, user_id, operation, credits_used, metadata, created_at)
   - `scans` (id, user_id, agent_name, status, findings, created_at, completed_at)

5. Run the development server:
   ```bash
   npm run dev
   ```

6. Open [http://localhost:3000](http://localhost:3000)

## Project Structure

```
aegis-app/
├── app/                      # Next.js App Router
│   ├── api/                  # API routes
│   │   ├── credits/          # Credit management
│   │   ├── keys/             # API key CRUD
│   │   ├── mcp/              # MCP proxy
│   │   ├── usage/            # Usage tracking
│   │   └── webhooks/         # Clerk & Stripe webhooks
│   ├── dashboard/            # Dashboard pages
│   │   ├── api-keys/
│   │   ├── billing/
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
│   ├── credits.ts            # Credit cost definitions
│   ├── stripe.ts             # Stripe integration
│   └── supabase.ts           # Supabase client
├── middleware.ts             # Clerk auth middleware
├── next.config.js
├── package.json
├── tailwind.config.js
└── tsconfig.json
```

## API Routes

### Authentication Required

- `GET /api/credits` - Get user credit balance
- `POST /api/credits` - Create Stripe checkout session
- `GET /api/keys` - List API keys
- `POST /api/keys` - Create new API key
- `DELETE /api/keys?id=<key_id>` - Delete API key
- `GET /api/usage` - Get usage history
- `POST /api/mcp/[...path]` - Proxy to NightOwl MCP

### Webhooks (No Auth)

- `POST /api/webhooks/clerk` - Clerk user events
- `POST /api/webhooks/stripe` - Stripe payment events

## Environment Variables

See `.env.example` for all required environment variables.

## Deployment

The easiest way to deploy is using [Vercel](https://vercel.com):

1. Push your code to GitHub
2. Import your repository in Vercel
3. Add all environment variables
4. Deploy

## Credits System

The app uses a credit-based system:

- **Basic Scan**: 30 credits
- **Advanced Scan**: 50 credits
- **Full Audit**: 100 credits
- **RAG Analysis**: 50 credits
- **Prompt Injection Test**: 40 credits
- **Tool Misuse Scan**: 35 credits
- **Data Leakage Check**: 45 credits

Users can purchase credit packages:
- 1,000 credits - $99
- 5,000 credits + 500 bonus - $449
- 10,000 credits + 1,500 bonus - $849

## License

MIT
