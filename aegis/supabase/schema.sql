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
