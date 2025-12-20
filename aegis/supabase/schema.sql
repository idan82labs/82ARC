-- ============================================================================
-- Aegis Security Platform - Supabase Database Schema
-- ============================================================================
-- This schema provides:
-- - User management (synced from Clerk)
-- - API key management with secure hashing
-- - Credit-based usage tracking
-- - Transaction history for billing
-- - Row-level security for multi-tenant isolation
-- ============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================================================
-- TABLES
-- ============================================================================

-- Users table (synced from Clerk)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clerk_id TEXT UNIQUE NOT NULL,
    email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT 'Default',
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Credits table
CREATE TABLE IF NOT EXISTS credits (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    balance INTEGER NOT NULL DEFAULT 500,
    tier TEXT NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'pro', 'enterprise')),
    monthly_refill INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Usage table
CREATE TABLE IF NOT EXISTS usage (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
    tool_name TEXT NOT NULL,
    credits_used INTEGER NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN ('purchase', 'refund', 'free_tier', 'monthly_refill')),
    amount_cents INTEGER,
    credits_added INTEGER NOT NULL,
    stripe_payment_id TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- INDEXES
-- ============================================================================

-- Users indexes
CREATE INDEX IF NOT EXISTS idx_users_clerk_id ON users(clerk_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- API Keys indexes
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_created_at ON api_keys(created_at);

-- Credits indexes
CREATE INDEX IF NOT EXISTS idx_credits_user_id ON credits(user_id);
CREATE INDEX IF NOT EXISTS idx_credits_tier ON credits(tier);

-- Usage indexes
CREATE INDEX IF NOT EXISTS idx_usage_user_id ON usage(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_api_key_id ON usage(api_key_id);
CREATE INDEX IF NOT EXISTS idx_usage_created_at ON usage(created_at);
CREATE INDEX IF NOT EXISTS idx_usage_tool_name ON usage(tool_name);
CREATE INDEX IF NOT EXISTS idx_usage_user_created ON usage(user_id, created_at);

-- Transactions indexes
CREATE INDEX IF NOT EXISTS idx_transactions_user_id ON transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_transactions_created_at ON transactions(created_at);
CREATE INDEX IF NOT EXISTS idx_transactions_type ON transactions(type);
CREATE INDEX IF NOT EXISTS idx_transactions_stripe_payment_id ON transactions(stripe_payment_id);

-- ============================================================================
-- FUNCTIONS
-- ============================================================================

-- Function: Update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function: Check if user has sufficient credits
CREATE OR REPLACE FUNCTION check_credits(p_user_id UUID, p_amount INTEGER)
RETURNS BOOLEAN AS $$
DECLARE
    v_balance INTEGER;
BEGIN
    -- Get current balance
    SELECT balance INTO v_balance
    FROM credits
    WHERE user_id = p_user_id;

    -- Return false if user not found or insufficient credits
    IF v_balance IS NULL THEN
        RETURN false;
    END IF;

    RETURN v_balance >= p_amount;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Atomically deduct credits
CREATE OR REPLACE FUNCTION deduct_credits(p_user_id UUID, p_amount INTEGER)
RETURNS BOOLEAN AS $$
DECLARE
    v_rows_affected INTEGER;
BEGIN
    -- Atomically deduct credits only if sufficient balance exists
    UPDATE credits
    SET
        balance = balance - p_amount,
        updated_at = NOW()
    WHERE
        user_id = p_user_id
        AND balance >= p_amount;

    GET DIAGNOSTICS v_rows_affected = ROW_COUNT;

    -- Return true if update was successful, false otherwise
    RETURN v_rows_affected > 0;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Add credits to user account
CREATE OR REPLACE FUNCTION add_credits(p_user_id UUID, p_amount INTEGER)
RETURNS BOOLEAN AS $$
BEGIN
    UPDATE credits
    SET
        balance = balance + p_amount,
        updated_at = NOW()
    WHERE user_id = p_user_id;

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Initialize credits for new user
CREATE OR REPLACE FUNCTION initialize_user_credits()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO credits (user_id, balance, tier, monthly_refill)
    VALUES (NEW.id, 500, 'free', 0);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- TRIGGERS
-- ============================================================================

-- Trigger: Auto-update updated_at on users table
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger: Auto-update updated_at on api_keys table
DROP TRIGGER IF EXISTS update_api_keys_updated_at ON api_keys;
CREATE TRIGGER update_api_keys_updated_at
    BEFORE UPDATE ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger: Initialize credits for new users
DROP TRIGGER IF EXISTS initialize_credits_on_user_creation ON users;
CREATE TRIGGER initialize_credits_on_user_creation
    AFTER INSERT ON users
    FOR EACH ROW
    EXECUTE FUNCTION initialize_user_credits();

-- ============================================================================
-- ROW LEVEL SECURITY (RLS)
-- ============================================================================

-- Enable RLS on all tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE credits ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- RLS POLICIES - USERS TABLE
-- ============================================================================

-- Users can read their own user record
CREATE POLICY users_select_own ON users
    FOR SELECT
    USING (auth.uid()::text = clerk_id);

-- Users can update their own user record
CREATE POLICY users_update_own ON users
    FOR UPDATE
    USING (auth.uid()::text = clerk_id)
    WITH CHECK (auth.uid()::text = clerk_id);

-- Service role can do everything (for Clerk webhook sync)
CREATE POLICY users_service_role_all ON users
    FOR ALL
    USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

-- ============================================================================
-- RLS POLICIES - API_KEYS TABLE
-- ============================================================================

-- Users can select their own API keys
CREATE POLICY api_keys_select_own ON api_keys
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = api_keys.user_id
            AND users.clerk_id = auth.uid()::text
        )
    );

-- Users can insert their own API keys
CREATE POLICY api_keys_insert_own ON api_keys
    FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = api_keys.user_id
            AND users.clerk_id = auth.uid()::text
        )
    );

-- Users can update their own API keys
CREATE POLICY api_keys_update_own ON api_keys
    FOR UPDATE
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = api_keys.user_id
            AND users.clerk_id = auth.uid()::text
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = api_keys.user_id
            AND users.clerk_id = auth.uid()::text
        )
    );

-- Users can delete their own API keys
CREATE POLICY api_keys_delete_own ON api_keys
    FOR DELETE
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = api_keys.user_id
            AND users.clerk_id = auth.uid()::text
        )
    );

-- Service role can do everything
CREATE POLICY api_keys_service_role_all ON api_keys
    FOR ALL
    USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

-- ============================================================================
-- RLS POLICIES - CREDITS TABLE
-- ============================================================================

-- Users can select their own credits
CREATE POLICY credits_select_own ON credits
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = credits.user_id
            AND users.clerk_id = auth.uid()::text
        )
    );

-- Users cannot directly update their credits (only through functions)
-- Service role can do everything
CREATE POLICY credits_service_role_all ON credits
    FOR ALL
    USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

-- ============================================================================
-- RLS POLICIES - USAGE TABLE
-- ============================================================================

-- Users can select their own usage records
CREATE POLICY usage_select_own ON usage
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = usage.user_id
            AND users.clerk_id = auth.uid()::text
        )
    );

-- Service role can do everything
CREATE POLICY usage_service_role_all ON usage
    FOR ALL
    USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

-- ============================================================================
-- RLS POLICIES - TRANSACTIONS TABLE
-- ============================================================================

-- Users can select their own transactions
CREATE POLICY transactions_select_own ON transactions
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = transactions.user_id
            AND users.clerk_id = auth.uid()::text
        )
    );

-- Service role can do everything
CREATE POLICY transactions_service_role_all ON transactions
    FOR ALL
    USING (auth.role() = 'service_role')
    WITH CHECK (auth.role() = 'service_role');

-- ============================================================================
-- HELPER VIEWS
-- ============================================================================

-- View: User dashboard statistics
CREATE OR REPLACE VIEW user_dashboard_stats AS
SELECT
    u.id as user_id,
    u.clerk_id,
    u.email,
    c.balance as current_credits,
    c.tier,
    c.monthly_refill,
    COUNT(DISTINCT ak.id) FILTER (WHERE ak.is_active = true) as active_api_keys,
    COALESCE(SUM(ug.credits_used), 0) as total_credits_used,
    COALESCE(SUM(ug.credits_used) FILTER (
        WHERE ug.created_at >= date_trunc('month', CURRENT_TIMESTAMP)
    ), 0) as credits_used_this_month,
    u.created_at as user_created_at
FROM users u
LEFT JOIN credits c ON c.user_id = u.id
LEFT JOIN api_keys ak ON ak.user_id = u.id
LEFT JOIN usage ug ON ug.user_id = u.id
GROUP BY u.id, u.clerk_id, u.email, c.balance, c.tier, c.monthly_refill, u.created_at;

-- View: Recent usage with details
CREATE OR REPLACE VIEW recent_usage_details AS
SELECT
    ug.id,
    ug.user_id,
    u.email,
    ug.tool_name,
    ug.credits_used,
    ak.name as api_key_name,
    ak.key_prefix,
    ug.metadata,
    ug.created_at
FROM usage ug
JOIN users u ON u.id = ug.user_id
LEFT JOIN api_keys ak ON ak.id = ug.api_key_id
ORDER BY ug.created_at DESC;

-- ============================================================================
-- SAMPLE DATA (Optional - for development/testing)
-- ============================================================================

-- Uncomment to insert sample data
/*
-- Sample user
INSERT INTO users (clerk_id, email)
VALUES ('user_test123', 'demo@example.com')
ON CONFLICT (clerk_id) DO NOTHING;

-- Credits will be automatically initialized by trigger
*/

-- ============================================================================
-- MIGRATIONS METADATA
-- ============================================================================

-- Track schema version
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO schema_migrations (version, description)
VALUES (1, 'Initial schema - Users, API Keys, Credits, Usage, Transactions')
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- END OF SCHEMA
-- ============================================================================

-- Grant necessary permissions to authenticated users
GRANT USAGE ON SCHEMA public TO authenticated;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO authenticated;

-- Grant permissions to service role for full access
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;
GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO service_role;

-- ============================================================================
-- ADMIN TABLES
-- ============================================================================

-- Admin users table (separate from regular users for role management)
CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'admin' CHECK (role IN ('admin', 'super_admin', 'readonly')),
    permissions JSONB DEFAULT '{"view_stats": true, "manage_users": false, "manage_credits": false}'::jsonb,
    granted_by UUID REFERENCES admin_users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id)
);

-- System health logs table
CREATE TABLE IF NOT EXISTS system_health_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name TEXT NOT NULL CHECK (service_name IN ('mcp_server', 'api', 'database', 'auth', 'billing')),
    status TEXT NOT NULL CHECK (status IN ('healthy', 'degraded', 'unhealthy', 'maintenance')),
    latency_ms INTEGER,
    error_count INTEGER DEFAULT 0,
    request_count INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Admin alerts table
CREATE TABLE IF NOT EXISTS admin_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    level TEXT NOT NULL CHECK (level IN ('info', 'warning', 'error', 'critical')),
    category TEXT NOT NULL CHECK (category IN ('security', 'performance', 'billing', 'system', 'user')),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata JSONB DEFAULT '{}'::jsonb,
    is_acknowledged BOOLEAN DEFAULT false,
    acknowledged_by UUID REFERENCES admin_users(id),
    acknowledged_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Security scans table
CREATE TABLE IF NOT EXISTS scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    scan_type TEXT NOT NULL,
    target_type TEXT NOT NULL CHECK (target_type IN ('llm', 'agent', 'rag', 'api', 'multimodal')),
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled')),
    credits_used INTEGER DEFAULT 0,
    results JSONB DEFAULT '{}'::jsonb,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Daily stats aggregation table (for fast admin queries)
CREATE TABLE IF NOT EXISTS daily_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    date DATE NOT NULL UNIQUE,
    total_users INTEGER DEFAULT 0,
    new_users INTEGER DEFAULT 0,
    active_users INTEGER DEFAULT 0,
    total_credits_used BIGINT DEFAULT 0,
    total_revenue_cents BIGINT DEFAULT 0,
    total_api_requests INTEGER DEFAULT 0,
    total_scans INTEGER DEFAULT 0,
    users_by_tier JSONB DEFAULT '{"free": 0, "pro": 0, "enterprise": 0}'::jsonb,
    top_tools JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ============================================================================
-- ADMIN INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_admin_users_user_id ON admin_users(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users(role);

CREATE INDEX IF NOT EXISTS idx_system_health_logs_service ON system_health_logs(service_name);
CREATE INDEX IF NOT EXISTS idx_system_health_logs_status ON system_health_logs(status);
CREATE INDEX IF NOT EXISTS idx_system_health_logs_recorded_at ON system_health_logs(recorded_at);

CREATE INDEX IF NOT EXISTS idx_admin_alerts_level ON admin_alerts(level);
CREATE INDEX IF NOT EXISTS idx_admin_alerts_category ON admin_alerts(category);
CREATE INDEX IF NOT EXISTS idx_admin_alerts_created_at ON admin_alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_admin_alerts_acknowledged ON admin_alerts(is_acknowledged);

CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_target_type ON scans(target_type);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);

CREATE INDEX IF NOT EXISTS idx_daily_stats_date ON daily_stats(date);

-- ============================================================================
-- ADMIN FUNCTIONS
-- ============================================================================

-- Function: Check if user is admin
CREATE OR REPLACE FUNCTION is_admin(p_user_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM admin_users
        WHERE user_id = p_user_id
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get admin overview stats
CREATE OR REPLACE FUNCTION get_admin_overview_stats()
RETURNS JSONB AS $$
DECLARE
    v_result JSONB;
BEGIN
    SELECT jsonb_build_object(
        'total_users', (SELECT COUNT(*) FROM users),
        'active_users_30d', (
            SELECT COUNT(DISTINCT user_id)
            FROM usage
            WHERE created_at >= NOW() - INTERVAL '30 days'
        ),
        'new_users_30d', (
            SELECT COUNT(*)
            FROM users
            WHERE created_at >= NOW() - INTERVAL '30 days'
        ),
        'total_credits_used', (SELECT COALESCE(SUM(credits_used), 0) FROM usage),
        'total_revenue_cents', (SELECT COALESCE(SUM(amount_cents), 0) FROM transactions WHERE type = 'purchase'),
        'active_scans', (SELECT COUNT(*) FROM scans WHERE status = 'running')
    ) INTO v_result;

    RETURN v_result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get users by tier
CREATE OR REPLACE FUNCTION get_users_by_tier()
RETURNS JSONB AS $$
BEGIN
    RETURN (
        SELECT jsonb_object_agg(tier, cnt)
        FROM (
            SELECT tier, COUNT(*) as cnt
            FROM credits
            GROUP BY tier
        ) t
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get credit usage by tool category
CREATE OR REPLACE FUNCTION get_credit_usage_by_category(p_days INTEGER DEFAULT 30)
RETURNS JSONB AS $$
DECLARE
    v_result JSONB;
BEGIN
    SELECT jsonb_object_agg(category, total_credits)
    INTO v_result
    FROM (
        SELECT
            CASE
                WHEN tool_name LIKE 'jailbreak%' THEN 'ai_attack_core'
                WHEN tool_name LIKE 'ai_fingerprint%' THEN 'ai_attack_core'
                WHEN tool_name LIKE 'prompt_injection%' THEN 'ai_attack_enhanced'
                WHEN tool_name LIKE 'rag_%' THEN 'ai_attack_enhanced'
                WHEN tool_name LIKE 'agent_%' THEN 'agent_attacks'
                WHEN tool_name LIKE 'mcp_%' THEN 'agent_attacks'
                WHEN tool_name LIKE 'multimodal%' THEN 'ai_attack_enhanced'
                WHEN tool_name LIKE 'function_calling%' THEN 'agent_attacks'
                WHEN tool_name LIKE 'subdomain%' OR tool_name LIKE 'tech_stack%' OR tool_name LIKE 'port_scan%' THEN 'recon'
                WHEN tool_name LIKE 'sql_injection%' OR tool_name LIKE 'xss_%' THEN 'vuln_scan'
                WHEN tool_name LIKE 'payload%' OR tool_name LIKE 'phishing%' THEN 'payload'
                ELSE 'other'
            END as category,
            SUM(credits_used) as total_credits
        FROM usage
        WHERE created_at >= NOW() - (p_days || ' days')::INTERVAL
        GROUP BY category
    ) t;

    RETURN COALESCE(v_result, '{}'::jsonb);
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get top tools by usage
CREATE OR REPLACE FUNCTION get_top_tools(p_days INTEGER DEFAULT 30, p_limit INTEGER DEFAULT 10)
RETURNS JSONB AS $$
BEGIN
    RETURN (
        SELECT jsonb_agg(row_to_json(t))
        FROM (
            SELECT
                tool_name as tool,
                COUNT(*) as usage_count,
                SUM(credits_used) as credits_used
            FROM usage
            WHERE created_at >= NOW() - (p_days || ' days')::INTERVAL
            GROUP BY tool_name
            ORDER BY credits_used DESC
            LIMIT p_limit
        ) t
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get daily usage stats
CREATE OR REPLACE FUNCTION get_daily_usage_stats(p_days INTEGER DEFAULT 30)
RETURNS JSONB AS $$
BEGIN
    RETURN (
        SELECT jsonb_agg(row_to_json(t))
        FROM (
            SELECT
                date_trunc('day', ug.created_at)::DATE as date,
                SUM(ug.credits_used) as credits_used,
                COUNT(DISTINCT ug.user_id) as active_users,
                (SELECT COUNT(*) FROM users WHERE date_trunc('day', created_at)::DATE = date_trunc('day', ug.created_at)::DATE) as new_signups,
                COALESCE((
                    SELECT SUM(amount_cents)::NUMERIC / 100
                    FROM transactions
                    WHERE type = 'purchase'
                    AND date_trunc('day', created_at)::DATE = date_trunc('day', ug.created_at)::DATE
                ), 0) as revenue
            FROM usage ug
            WHERE ug.created_at >= NOW() - (p_days || ' days')::INTERVAL
            GROUP BY date_trunc('day', ug.created_at)::DATE
            ORDER BY date
        ) t
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get recent signups
CREATE OR REPLACE FUNCTION get_recent_signups(p_limit INTEGER DEFAULT 10)
RETURNS JSONB AS $$
BEGIN
    RETURN (
        SELECT jsonb_agg(row_to_json(t))
        FROM (
            SELECT
                u.id,
                u.email,
                c.tier,
                u.created_at as signed_up
            FROM users u
            JOIN credits c ON c.user_id = u.id
            ORDER BY u.created_at DESC
            LIMIT p_limit
        ) t
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get top users by usage
CREATE OR REPLACE FUNCTION get_top_users_by_usage(p_days INTEGER DEFAULT 30, p_limit INTEGER DEFAULT 10)
RETURNS JSONB AS $$
BEGIN
    RETURN (
        SELECT jsonb_agg(row_to_json(t))
        FROM (
            SELECT
                u.id,
                u.email,
                c.tier,
                SUM(ug.credits_used) as credits_used,
                MAX(ug.created_at) as last_active
            FROM users u
            JOIN credits c ON c.user_id = u.id
            JOIN usage ug ON ug.user_id = u.id
            WHERE ug.created_at >= NOW() - (p_days || ' days')::INTERVAL
            GROUP BY u.id, u.email, c.tier
            ORDER BY credits_used DESC
            LIMIT p_limit
        ) t
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get system health
CREATE OR REPLACE FUNCTION get_system_health()
RETURNS JSONB AS $$
DECLARE
    v_result JSONB;
BEGIN
    SELECT jsonb_build_object(
        'mcp_server_status', COALESCE(
            (SELECT status FROM system_health_logs WHERE service_name = 'mcp_server' ORDER BY recorded_at DESC LIMIT 1),
            'unknown'
        ),
        'mcp_server_latency_ms', COALESCE(
            (SELECT latency_ms FROM system_health_logs WHERE service_name = 'mcp_server' ORDER BY recorded_at DESC LIMIT 1),
            0
        ),
        'api_requests_24h', COALESCE(
            (SELECT SUM(request_count) FROM system_health_logs WHERE service_name = 'api' AND recorded_at >= NOW() - INTERVAL '24 hours'),
            0
        ),
        'api_errors_24h', COALESCE(
            (SELECT SUM(error_count) FROM system_health_logs WHERE service_name = 'api' AND recorded_at >= NOW() - INTERVAL '24 hours'),
            0
        )
    ) INTO v_result;

    RETURN v_result;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get active alerts
CREATE OR REPLACE FUNCTION get_active_alerts(p_limit INTEGER DEFAULT 10)
RETURNS JSONB AS $$
BEGIN
    RETURN (
        SELECT jsonb_agg(row_to_json(t))
        FROM (
            SELECT
                level,
                category,
                title,
                message,
                created_at as timestamp
            FROM admin_alerts
            WHERE is_acknowledged = false
            ORDER BY
                CASE level
                    WHEN 'critical' THEN 1
                    WHEN 'error' THEN 2
                    WHEN 'warning' THEN 3
                    ELSE 4
                END,
                created_at DESC
            LIMIT p_limit
        ) t
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Get revenue by tier
CREATE OR REPLACE FUNCTION get_revenue_by_tier(p_days INTEGER DEFAULT 30)
RETURNS JSONB AS $$
BEGIN
    RETURN (
        SELECT jsonb_object_agg(tier_type, revenue)
        FROM (
            SELECT
                CASE
                    WHEN c.tier = 'pro' THEN 'pro'
                    WHEN c.tier = 'enterprise' THEN 'enterprise'
                    ELSE 'credit_topups'
                END as tier_type,
                SUM(t.amount_cents)::NUMERIC / 100 as revenue
            FROM transactions t
            JOIN users u ON u.id = t.user_id
            JOIN credits c ON c.user_id = u.id
            WHERE t.type = 'purchase'
            AND t.created_at >= NOW() - (p_days || ' days')::INTERVAL
            GROUP BY tier_type
        ) sub
    );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Aggregate daily stats (run as a cron job)
CREATE OR REPLACE FUNCTION aggregate_daily_stats(p_date DATE DEFAULT CURRENT_DATE - 1)
RETURNS VOID AS $$
BEGIN
    INSERT INTO daily_stats (
        date,
        total_users,
        new_users,
        active_users,
        total_credits_used,
        total_revenue_cents,
        total_api_requests,
        total_scans,
        users_by_tier,
        top_tools
    )
    VALUES (
        p_date,
        (SELECT COUNT(*) FROM users WHERE created_at::DATE <= p_date),
        (SELECT COUNT(*) FROM users WHERE created_at::DATE = p_date),
        (SELECT COUNT(DISTINCT user_id) FROM usage WHERE created_at::DATE = p_date),
        (SELECT COALESCE(SUM(credits_used), 0) FROM usage WHERE created_at::DATE = p_date),
        (SELECT COALESCE(SUM(amount_cents), 0) FROM transactions WHERE type = 'purchase' AND created_at::DATE = p_date),
        (SELECT COALESCE(SUM(request_count), 0) FROM system_health_logs WHERE service_name = 'api' AND recorded_at::DATE = p_date),
        (SELECT COUNT(*) FROM scans WHERE created_at::DATE = p_date),
        (SELECT jsonb_object_agg(tier, cnt) FROM (SELECT tier, COUNT(*) as cnt FROM credits GROUP BY tier) t),
        (SELECT jsonb_agg(row_to_json(t)) FROM (
            SELECT tool_name as tool, COUNT(*) as usage_count, SUM(credits_used) as credits_used
            FROM usage WHERE created_at::DATE = p_date
            GROUP BY tool_name ORDER BY credits_used DESC LIMIT 10
        ) t)
    )
    ON CONFLICT (date) DO UPDATE SET
        total_users = EXCLUDED.total_users,
        new_users = EXCLUDED.new_users,
        active_users = EXCLUDED.active_users,
        total_credits_used = EXCLUDED.total_credits_used,
        total_revenue_cents = EXCLUDED.total_revenue_cents,
        total_api_requests = EXCLUDED.total_api_requests,
        total_scans = EXCLUDED.total_scans,
        users_by_tier = EXCLUDED.users_by_tier,
        top_tools = EXCLUDED.top_tools,
        updated_at = NOW();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Log system health
CREATE OR REPLACE FUNCTION log_system_health(
    p_service TEXT,
    p_status TEXT,
    p_latency_ms INTEGER DEFAULT NULL,
    p_request_count INTEGER DEFAULT 0,
    p_error_count INTEGER DEFAULT 0,
    p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS UUID AS $$
DECLARE
    v_id UUID;
BEGIN
    INSERT INTO system_health_logs (
        service_name, status, latency_ms, request_count, error_count, metadata
    )
    VALUES (
        p_service, p_status, p_latency_ms, p_request_count, p_error_count, p_metadata
    )
    RETURNING id INTO v_id;

    -- Create alert if unhealthy
    IF p_status = 'unhealthy' THEN
        INSERT INTO admin_alerts (level, category, title, message, metadata)
        VALUES (
            'error',
            'system',
            p_service || ' service unhealthy',
            'The ' || p_service || ' service has reported an unhealthy status.',
            jsonb_build_object('service', p_service, 'health_log_id', v_id)
        );
    END IF;

    RETURN v_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Create admin alert
CREATE OR REPLACE FUNCTION create_admin_alert(
    p_level TEXT,
    p_category TEXT,
    p_title TEXT,
    p_message TEXT,
    p_metadata JSONB DEFAULT '{}'::jsonb
)
RETURNS UUID AS $$
DECLARE
    v_id UUID;
BEGIN
    INSERT INTO admin_alerts (level, category, title, message, metadata)
    VALUES (p_level, p_category, p_title, p_message, p_metadata)
    RETURNING id INTO v_id;

    RETURN v_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Function: Acknowledge alert
CREATE OR REPLACE FUNCTION acknowledge_alert(p_alert_id UUID, p_admin_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
    UPDATE admin_alerts
    SET
        is_acknowledged = true,
        acknowledged_by = p_admin_id,
        acknowledged_at = NOW()
    WHERE id = p_alert_id;

    RETURN FOUND;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- ADMIN RLS POLICIES
-- ============================================================================

ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_health_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE daily_stats ENABLE ROW LEVEL SECURITY;

-- Admin users: Only admins can view admin list
CREATE POLICY admin_users_select ON admin_users
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM admin_users au
            JOIN users u ON u.id = au.user_id
            WHERE u.clerk_id = auth.uid()::text
        )
    );

-- System health: Only admins can view
CREATE POLICY system_health_select ON system_health_logs
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM admin_users au
            JOIN users u ON u.id = au.user_id
            WHERE u.clerk_id = auth.uid()::text
        )
    );

-- Admin alerts: Only admins can view
CREATE POLICY admin_alerts_select ON admin_alerts
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM admin_users au
            JOIN users u ON u.id = au.user_id
            WHERE u.clerk_id = auth.uid()::text
        )
    );

-- Scans: Users can see their own scans
CREATE POLICY scans_select_own ON scans
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = scans.user_id
            AND users.clerk_id = auth.uid()::text
        )
    );

-- Scans: Users can insert their own scans
CREATE POLICY scans_insert_own ON scans
    FOR INSERT
    WITH CHECK (
        EXISTS (
            SELECT 1 FROM users
            WHERE users.id = scans.user_id
            AND users.clerk_id = auth.uid()::text
        )
    );

-- Daily stats: Only admins can view
CREATE POLICY daily_stats_select ON daily_stats
    FOR SELECT
    USING (
        EXISTS (
            SELECT 1 FROM admin_users au
            JOIN users u ON u.id = au.user_id
            WHERE u.clerk_id = auth.uid()::text
        )
    );

-- Service role policies for admin tables
CREATE POLICY admin_users_service_role ON admin_users FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY system_health_service_role ON system_health_logs FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY admin_alerts_service_role ON admin_alerts FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY scans_service_role ON scans FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY daily_stats_service_role ON daily_stats FOR ALL USING (auth.role() = 'service_role');

-- ============================================================================
-- ADMIN VIEWS
-- ============================================================================

-- View: Admin dashboard overview
CREATE OR REPLACE VIEW admin_dashboard_overview AS
SELECT
    (SELECT COUNT(*) FROM users) as total_users,
    (SELECT COUNT(DISTINCT user_id) FROM usage WHERE created_at >= NOW() - INTERVAL '30 days') as active_users_30d,
    (SELECT COUNT(*) FROM users WHERE created_at >= NOW() - INTERVAL '30 days') as new_users_30d,
    (SELECT COALESCE(SUM(credits_used), 0) FROM usage) as total_credits_used,
    (SELECT COALESCE(SUM(amount_cents), 0)::NUMERIC / 100 FROM transactions WHERE type = 'purchase') as total_revenue,
    (SELECT COUNT(*) FROM scans WHERE status = 'running') as active_operations;

-- View: Tool usage summary
CREATE OR REPLACE VIEW tool_usage_summary AS
SELECT
    tool_name,
    COUNT(*) as usage_count,
    SUM(credits_used) as total_credits,
    COUNT(DISTINCT user_id) as unique_users,
    MAX(created_at) as last_used
FROM usage
GROUP BY tool_name
ORDER BY total_credits DESC;

-- View: User engagement metrics
CREATE OR REPLACE VIEW user_engagement_metrics AS
SELECT
    u.id as user_id,
    u.email,
    c.tier,
    c.balance as current_credits,
    COALESCE(SUM(ug.credits_used), 0) as total_credits_used,
    COUNT(DISTINCT DATE(ug.created_at)) as active_days,
    MAX(ug.created_at) as last_active,
    u.created_at as signed_up
FROM users u
JOIN credits c ON c.user_id = u.id
LEFT JOIN usage ug ON ug.user_id = u.id
GROUP BY u.id, u.email, c.tier, c.balance, u.created_at
ORDER BY total_credits_used DESC;

-- ============================================================================
-- TRIGGERS FOR ADMIN TABLES
-- ============================================================================

-- Trigger: Auto-update updated_at on admin_users
DROP TRIGGER IF EXISTS update_admin_users_updated_at ON admin_users;
CREATE TRIGGER update_admin_users_updated_at
    BEFORE UPDATE ON admin_users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Trigger: Auto-update updated_at on daily_stats
DROP TRIGGER IF EXISTS update_daily_stats_updated_at ON daily_stats;
CREATE TRIGGER update_daily_stats_updated_at
    BEFORE UPDATE ON daily_stats
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- UPDATE SCHEMA VERSION
-- ============================================================================

INSERT INTO schema_migrations (version, description)
VALUES (2, 'Admin dashboard tables - admin_users, system_health_logs, admin_alerts, scans, daily_stats')
ON CONFLICT (version) DO NOTHING;

-- ============================================================================
-- NOTES
-- ============================================================================
--
-- 1. API Key Security:
--    - Store only SHA256 hashes of API keys in key_hash
--    - Store first 8 chars in key_prefix for user identification
--    - Never store the full API key in the database
--
-- 2. Credit Management:
--    - Use deduct_credits() function for atomic credit deduction
--    - Use check_credits() to verify before performing operations
--    - Credits are automatically initialized to 500 for new users
--
-- 3. RLS Policies:
--    - All user data is isolated by clerk_id
--    - Service role bypasses RLS for backend operations
--    - Users can only read/modify their own data
--
-- 4. Indexing Strategy:
--    - Indexes on foreign keys for JOIN performance
--    - Indexes on commonly queried fields (created_at, user_id)
--    - Composite index on usage(user_id, created_at) for efficient queries
--
-- 5. Clerk Integration:
--    - Use clerk_id as the authoritative user identifier
--    - Sync users via Clerk webhooks using service role
--    - auth.uid() returns the Clerk user ID in RLS policies
--
-- ============================================================================
