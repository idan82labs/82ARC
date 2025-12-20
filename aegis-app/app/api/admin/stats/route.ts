import { NextRequest, NextResponse } from 'next/server';

// Admin role check - in production, verify from Clerk/Supabase
async function isAdmin(request: NextRequest): Promise<boolean> {
  const authHeader = request.headers.get('authorization');
  const apiKey = request.headers.get('x-api-key');

  // For development/demo - check for admin API key
  if (apiKey === process.env.ADMIN_API_KEY || apiKey === 'admin_dev_key') {
    return true;
  }

  // In production, verify Clerk session and check admin role
  // const { userId } = auth();
  // const user = await clerkClient.users.getUser(userId);
  // return user.publicMetadata.role === 'admin';

  return false;
}

// Mock data for demo - in production, query Supabase
function getMockStats() {
  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);

  return {
    overview: {
      total_users: 1247,
      active_users_30d: 834,
      new_users_30d: 156,
      total_credits_used: 2847563,
      total_revenue: 28475.63,
      active_operations: 23,
      avg_session_duration: '14m 32s',
    },

    users_by_tier: {
      free: 892,
      pro: 287,
      enterprise: 68,
    },

    credit_usage_by_category: {
      ai_attack_core: 847234,
      ai_attack_enhanced: 423617,
      agent_attacks: 634892,
      recon: 234567,
      vuln_scan: 345678,
      payload: 189234,
      infrastructure: 172341,
    },

    top_tools_30d: [
      { tool: 'jailbreak_adaptive', usage_count: 12847, credits_used: 1284700 },
      { tool: 'ai_fingerprint_enhanced', usage_count: 9823, credits_used: 736725 },
      { tool: 'agent_goal_hijack', usage_count: 8234, credits_used: 617550 },
      { tool: 'prompt_injection_generate', usage_count: 7891, credits_used: 394550 },
      { tool: 'jailbreak_crescendo', usage_count: 6234, credits_used: 935100 },
      { tool: 'rag_poisoning_craft', usage_count: 5678, credits_used: 567800 },
      { tool: 'multimodal_injection', usage_count: 4923, credits_used: 369225 },
      { tool: 'agent_test_suite', usage_count: 3456, credits_used: 691200 },
      { tool: 'function_calling_attack', usage_count: 3234, credits_used: 242550 },
      { tool: 'agent_mcp_attack', usage_count: 2891, credits_used: 361375 },
    ],

    daily_usage_30d: Array.from({ length: 30 }, (_, i) => {
      const date = new Date(thirtyDaysAgo.getTime() + i * 24 * 60 * 60 * 1000);
      const baseCredits = 80000 + Math.floor(Math.random() * 40000);
      const baseUsers = 200 + Math.floor(Math.random() * 100);
      return {
        date: date.toISOString().split('T')[0],
        credits_used: baseCredits + (i > 20 ? 20000 : 0), // trend up
        active_users: baseUsers + Math.floor(i * 2),
        new_signups: 3 + Math.floor(Math.random() * 8),
        revenue: baseCredits / 100,
      };
    }),

    revenue_by_tier: {
      pro: 14350.00,
      enterprise: 12875.63,
      credit_topups: 1250.00,
    },

    system_health: {
      mcp_server_status: 'healthy',
      mcp_server_uptime: '99.97%',
      mcp_server_latency_ms: 145,
      api_requests_24h: 34567,
      api_errors_24h: 23,
      api_error_rate: '0.07%',
      database_connections: 45,
      database_pool_size: 100,
      cache_hit_rate: '94.3%',
    },

    recent_signups: [
      { id: 'usr_abc123', email: 'alice@example.com', tier: 'pro', signed_up: '2025-12-19T14:32:00Z' },
      { id: 'usr_def456', email: 'bob@startup.io', tier: 'enterprise', signed_up: '2025-12-19T12:15:00Z' },
      { id: 'usr_ghi789', email: 'charlie@security.co', tier: 'free', signed_up: '2025-12-19T10:45:00Z' },
      { id: 'usr_jkl012', email: 'diana@pentest.net', tier: 'pro', signed_up: '2025-12-18T22:30:00Z' },
      { id: 'usr_mno345', email: 'eve@redteam.io', tier: 'free', signed_up: '2025-12-18T18:20:00Z' },
    ],

    top_users_by_usage: [
      { id: 'usr_ent001', email: 'enterprise1@corp.com', tier: 'enterprise', credits_used: 45678, last_active: '2025-12-20T08:30:00Z' },
      { id: 'usr_ent002', email: 'security@bigtech.io', tier: 'enterprise', credits_used: 38234, last_active: '2025-12-20T07:45:00Z' },
      { id: 'usr_pro001', email: 'pentester@agency.co', tier: 'pro', credits_used: 28934, last_active: '2025-12-20T09:15:00Z' },
      { id: 'usr_ent003', email: 'redteam@finance.com', tier: 'enterprise', credits_used: 25678, last_active: '2025-12-19T23:30:00Z' },
      { id: 'usr_pro002', email: 'researcher@lab.edu', tier: 'pro', credits_used: 19234, last_active: '2025-12-20T06:00:00Z' },
    ],

    alerts: [
      { level: 'warning', message: 'High API latency detected (>500ms) at 03:45 UTC', timestamp: '2025-12-20T03:45:00Z' },
      { level: 'info', message: 'Scheduled maintenance window: Dec 22, 02:00-04:00 UTC', timestamp: '2025-12-19T10:00:00Z' },
    ],

    generated_at: now.toISOString(),
  };
}

export async function GET(request: NextRequest) {
  // Check admin authorization
  const authorized = await isAdmin(request);

  if (!authorized) {
    return NextResponse.json(
      { error: 'Unauthorized. Admin access required.' },
      { status: 401 }
    );
  }

  try {
    // In production, query Supabase for real data
    // const supabase = createClient(...)
    // const { data: users } = await supabase.from('users').select('*')
    // const { data: usage } = await supabase.from('usage_logs').select('*')

    const stats = getMockStats();

    return NextResponse.json(stats);
  } catch (error) {
    console.error('Admin stats error:', error);
    return NextResponse.json(
      { error: 'Failed to fetch admin stats' },
      { status: 500 }
    );
  }
}

// POST endpoint for admin actions
export async function POST(request: NextRequest) {
  const authorized = await isAdmin(request);

  if (!authorized) {
    return NextResponse.json(
      { error: 'Unauthorized. Admin access required.' },
      { status: 401 }
    );
  }

  try {
    const body = await request.json();
    const { action, target } = body;

    switch (action) {
      case 'refresh_cache':
        // Clear and refresh stats cache
        return NextResponse.json({ success: true, message: 'Cache refreshed' });

      case 'export_report':
        // Generate exportable report
        const stats = getMockStats();
        return NextResponse.json({
          success: true,
          report: stats,
          format: 'json',
          generated_at: new Date().toISOString()
        });

      case 'adjust_credits':
        // Adjust user credits (admin action)
        const { user_id, amount, reason } = target || {};
        if (!user_id || !amount) {
          return NextResponse.json({ error: 'Missing user_id or amount' }, { status: 400 });
        }
        // In production: update Supabase
        return NextResponse.json({
          success: true,
          message: `Adjusted ${amount} credits for user ${user_id}`,
          reason
        });

      case 'disable_user':
        // Disable a user account
        const { target_user_id } = target || {};
        if (!target_user_id) {
          return NextResponse.json({ error: 'Missing target_user_id' }, { status: 400 });
        }
        return NextResponse.json({
          success: true,
          message: `User ${target_user_id} disabled`
        });

      default:
        return NextResponse.json({ error: 'Unknown action' }, { status: 400 });
    }
  } catch (error) {
    console.error('Admin action error:', error);
    return NextResponse.json(
      { error: 'Failed to execute admin action' },
      { status: 500 }
    );
  }
}
