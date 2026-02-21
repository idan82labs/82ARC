'use client';

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Users,
  CreditCard,
  Activity,
  TrendingUp,
  Server,
  AlertTriangle,
  Shield,
  Clock,
  Database,
  Zap,
  RefreshCw,
  Download,
  ChevronUp,
  ChevronDown,
  AlertCircle,
  CheckCircle,
  Info,
} from 'lucide-react';
import { Sidebar } from '@/components/dashboard/Sidebar';
import { Button } from '@/components/ui/Button';

interface AdminStats {
  overview: {
    total_users: number;
    active_users_30d: number;
    new_users_30d: number;
    total_credits_used: number;
    total_revenue: number;
    active_operations: number;
    avg_session_duration: string;
  };
  users_by_tier: {
    free: number;
    pro: number;
    enterprise: number;
  };
  credit_usage_by_category: Record<string, number>;
  top_tools_30d: Array<{ tool: string; usage_count: number; credits_used: number }>;
  daily_usage_30d: Array<{
    date: string;
    credits_used: number;
    active_users: number;
    new_signups: number;
    revenue: number;
  }>;
  revenue_by_tier: Record<string, number>;
  system_health: {
    mcp_server_status: string;
    mcp_server_uptime: string;
    mcp_server_latency_ms: number;
    api_requests_24h: number;
    api_errors_24h: number;
    api_error_rate: string;
    database_connections: number;
    database_pool_size: number;
    cache_hit_rate: string;
  };
  recent_signups: Array<{ id: string; email: string; tier: string; signed_up: string }>;
  top_users_by_usage: Array<{
    id: string;
    email: string;
    tier: string;
    credits_used: number;
    last_active: string;
  }>;
  alerts: Array<{ level: string; message: string; timestamp: string }>;
  generated_at: string;
}

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  trend,
  color = 'blue',
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: any;
  trend?: { value: number; positive: boolean };
  color?: string;
}) {
  const colorClasses = {
    blue: 'bg-blue-50 text-blue-600',
    green: 'bg-green-50 text-green-600',
    purple: 'bg-purple-50 text-purple-600',
    amber: 'bg-amber-50 text-amber-600',
    red: 'bg-red-50 text-red-600',
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-white rounded-xl border border-slate-200 p-6"
    >
      <div className="flex items-start justify-between mb-4">
        <div className={`p-3 rounded-lg ${colorClasses[color as keyof typeof colorClasses]}`}>
          <Icon size={24} />
        </div>
        {trend && (
          <div
            className={`flex items-center gap-1 text-sm font-medium ${
              trend.positive ? 'text-green-600' : 'text-red-600'
            }`}
          >
            {trend.positive ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
            {Math.abs(trend.value)}%
          </div>
        )}
      </div>
      <div className="text-2xl font-bold text-slate-900 mb-1">
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      <div className="text-sm text-slate-500">{title}</div>
      {subtitle && <div className="text-xs text-slate-400 mt-1">{subtitle}</div>}
    </motion.div>
  );
}

function MiniBarChart({ data, maxValue }: { data: number[]; maxValue: number }) {
  return (
    <div className="flex items-end gap-1 h-12">
      {data.slice(-14).map((value, i) => (
        <div
          key={i}
          className="flex-1 bg-blue-500 rounded-t"
          style={{ height: `${(value / maxValue) * 100}%`, minHeight: '2px' }}
        />
      ))}
    </div>
  );
}

function ProgressBar({
  value,
  max,
  label,
  color = 'blue',
}: {
  value: number;
  max: number;
  label: string;
  color?: string;
}) {
  const percentage = (value / max) * 100;
  const colorClasses = {
    blue: 'bg-blue-500',
    green: 'bg-green-500',
    purple: 'bg-purple-500',
    amber: 'bg-amber-500',
  };

  return (
    <div className="mb-3">
      <div className="flex justify-between text-sm mb-1">
        <span className="text-slate-600">{label}</span>
        <span className="font-medium text-slate-900">{value.toLocaleString()}</span>
      </div>
      <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
        <div
          className={`h-full ${colorClasses[color as keyof typeof colorClasses]} rounded-full transition-all`}
          style={{ width: `${Math.min(percentage, 100)}%` }}
        />
      </div>
    </div>
  );
}

export default function AdminDashboardPage() {
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const fetchStats = async () => {
    try {
      setRefreshing(true);
      const response = await fetch('/api/admin/stats', {
        headers: {
          'x-api-key': 'admin_dev_key', // In production, use proper auth
        },
      });

      if (!response.ok) {
        if (response.status === 401) {
          throw new Error('Unauthorized. Admin access required.');
        }
        throw new Error('Failed to fetch stats');
      }

      const data = await response.json();
      setStats(data);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    fetchStats();
    // Auto-refresh every 5 minutes
    const interval = setInterval(fetchStats, 5 * 60 * 1000);
    return () => clearInterval(interval);
  }, []);

  const handleExport = async () => {
    try {
      const response = await fetch('/api/admin/stats', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': 'admin_dev_key',
        },
        body: JSON.stringify({ action: 'export_report' }),
      });
      const data = await response.json();

      // Download as JSON file
      const blob = new Blob([JSON.stringify(data.report, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `aegis-admin-report-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
    } catch (err) {
      console.error('Export failed:', err);
    }
  };

  if (loading) {
    return (
      <div className="flex min-h-screen bg-slate-50">
        <Sidebar />
        <main className="flex-1 p-8 flex items-center justify-center">
          <div className="text-center">
            <RefreshCw size={32} className="animate-spin text-blue-600 mx-auto mb-4" />
            <p className="text-slate-500">Loading admin dashboard...</p>
          </div>
        </main>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex min-h-screen bg-slate-50">
        <Sidebar />
        <main className="flex-1 p-8 flex items-center justify-center">
          <div className="text-center bg-white p-8 rounded-xl border border-red-200">
            <AlertTriangle size={32} className="text-red-500 mx-auto mb-4" />
            <h2 className="text-xl font-bold text-slate-900 mb-2">Access Denied</h2>
            <p className="text-slate-500 mb-4">{error}</p>
            <Button variant="primary" onClick={fetchStats}>
              Retry
            </Button>
          </div>
        </main>
      </div>
    );
  }

  if (!stats) return null;

  const totalUsers =
    stats.users_by_tier.free + stats.users_by_tier.pro + stats.users_by_tier.enterprise;
  const maxCreditsPerCategory = Math.max(...Object.values(stats.credit_usage_by_category));

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8 overflow-auto">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-3xl font-bold text-slate-900 mb-2">Admin Dashboard</h1>
              <p className="text-slate-500">
                System overview and analytics
                <span className="text-xs text-slate-400 ml-2">
                  Updated: {new Date(stats.generated_at).toLocaleString()}
                </span>
              </p>
            </div>
            <div className="flex gap-3">
              <Button variant="secondary" onClick={fetchStats} disabled={refreshing}>
                <RefreshCw size={16} className={refreshing ? 'animate-spin' : ''} />
                Refresh
              </Button>
              <Button variant="primary" onClick={handleExport}>
                <Download size={16} />
                Export Report
              </Button>
            </div>
          </div>

          {/* Alerts */}
          {stats.alerts.length > 0 && (
            <div className="mb-6 space-y-2">
              {stats.alerts.map((alert, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className={`flex items-center gap-3 p-4 rounded-lg border ${
                    alert.level === 'warning'
                      ? 'bg-amber-50 border-amber-200 text-amber-800'
                      : alert.level === 'error'
                      ? 'bg-red-50 border-red-200 text-red-800'
                      : 'bg-blue-50 border-blue-200 text-blue-800'
                  }`}
                >
                  {alert.level === 'warning' ? (
                    <AlertCircle size={20} />
                  ) : alert.level === 'error' ? (
                    <AlertTriangle size={20} />
                  ) : (
                    <Info size={20} />
                  )}
                  <span className="flex-1">{alert.message}</span>
                  <span className="text-xs opacity-75">
                    {new Date(alert.timestamp).toLocaleString()}
                  </span>
                </motion.div>
              ))}
            </div>
          )}

          {/* Overview Stats */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <StatCard
              title="Total Users"
              value={stats.overview.total_users}
              subtitle={`${stats.overview.new_users_30d} new this month`}
              icon={Users}
              trend={{ value: 12.5, positive: true }}
              color="blue"
            />
            <StatCard
              title="Active Users (30d)"
              value={stats.overview.active_users_30d}
              subtitle={`${((stats.overview.active_users_30d / stats.overview.total_users) * 100).toFixed(1)}% of total`}
              icon={Activity}
              trend={{ value: 8.3, positive: true }}
              color="green"
            />
            <StatCard
              title="Credits Used"
              value={stats.overview.total_credits_used.toLocaleString()}
              subtitle="All time"
              icon={Zap}
              trend={{ value: 15.2, positive: true }}
              color="purple"
            />
            <StatCard
              title="Total Revenue"
              value={`$${stats.overview.total_revenue.toLocaleString()}`}
              subtitle="All time"
              icon={CreditCard}
              trend={{ value: 22.1, positive: true }}
              color="amber"
            />
          </div>

          {/* System Health + Users by Tier */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            {/* System Health */}
            <div className="bg-white rounded-xl border border-slate-200 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Server size={20} className="text-slate-600" />
                <h3 className="font-semibold text-slate-900">System Health</h3>
              </div>

              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-600">MCP Server</span>
                  <div className="flex items-center gap-2">
                    <CheckCircle size={16} className="text-green-500" />
                    <span className="text-sm font-medium text-green-600">
                      {stats.system_health.mcp_server_status}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-600">Uptime</span>
                  <span className="text-sm font-medium text-slate-900">
                    {stats.system_health.mcp_server_uptime}
                  </span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-sm text-slate-600">Latency</span>
                  <span
                    className={`text-sm font-medium ${
                      stats.system_health.mcp_server_latency_ms < 200
                        ? 'text-green-600'
                        : stats.system_health.mcp_server_latency_ms < 500
                        ? 'text-amber-600'
                        : 'text-red-600'
                    }`}
                  >
                    {stats.system_health.mcp_server_latency_ms}ms
                  </span>
                </div>

                <div className="pt-3 border-t border-slate-100">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-slate-600">API Requests (24h)</span>
                    <span className="text-sm font-medium text-slate-900">
                      {stats.system_health.api_requests_24h.toLocaleString()}
                    </span>
                  </div>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-slate-600">Error Rate</span>
                    <span
                      className={`text-sm font-medium ${
                        parseFloat(stats.system_health.api_error_rate) < 1
                          ? 'text-green-600'
                          : 'text-red-600'
                      }`}
                    >
                      {stats.system_health.api_error_rate}
                    </span>
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-600">Cache Hit Rate</span>
                    <span className="text-sm font-medium text-green-600">
                      {stats.system_health.cache_hit_rate}
                    </span>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-100">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-slate-600">DB Connections</span>
                    <span className="text-sm font-medium text-slate-900">
                      {stats.system_health.database_connections} / {stats.system_health.database_pool_size}
                    </span>
                  </div>
                  <div className="h-2 bg-slate-100 rounded-full mt-2 overflow-hidden">
                    <div
                      className="h-full bg-blue-500 rounded-full"
                      style={{
                        width: `${
                          (stats.system_health.database_connections /
                            stats.system_health.database_pool_size) *
                          100
                        }%`,
                      }}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Users by Tier */}
            <div className="bg-white rounded-xl border border-slate-200 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Users size={20} className="text-slate-600" />
                <h3 className="font-semibold text-slate-900">Users by Tier</h3>
              </div>

              <div className="space-y-4">
                <ProgressBar
                  value={stats.users_by_tier.free}
                  max={totalUsers}
                  label="Free"
                  color="blue"
                />
                <ProgressBar
                  value={stats.users_by_tier.pro}
                  max={totalUsers}
                  label="Pro"
                  color="purple"
                />
                <ProgressBar
                  value={stats.users_by_tier.enterprise}
                  max={totalUsers}
                  label="Enterprise"
                  color="amber"
                />
              </div>

              <div className="mt-6 pt-4 border-t border-slate-100">
                <div className="grid grid-cols-3 gap-4 text-center">
                  <div>
                    <div className="text-2xl font-bold text-slate-900">
                      {((stats.users_by_tier.free / totalUsers) * 100).toFixed(0)}%
                    </div>
                    <div className="text-xs text-slate-500">Free</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-purple-600">
                      {((stats.users_by_tier.pro / totalUsers) * 100).toFixed(0)}%
                    </div>
                    <div className="text-xs text-slate-500">Pro</div>
                  </div>
                  <div>
                    <div className="text-2xl font-bold text-amber-600">
                      {((stats.users_by_tier.enterprise / totalUsers) * 100).toFixed(0)}%
                    </div>
                    <div className="text-xs text-slate-500">Enterprise</div>
                  </div>
                </div>
              </div>
            </div>

            {/* Revenue by Tier */}
            <div className="bg-white rounded-xl border border-slate-200 p-6">
              <div className="flex items-center gap-2 mb-4">
                <CreditCard size={20} className="text-slate-600" />
                <h3 className="font-semibold text-slate-900">Revenue Breakdown</h3>
              </div>

              <div className="space-y-4">
                {Object.entries(stats.revenue_by_tier).map(([tier, amount]) => (
                  <div key={tier} className="flex items-center justify-between">
                    <span className="text-sm text-slate-600 capitalize">
                      {tier.replace('_', ' ')}
                    </span>
                    <span className="text-sm font-bold text-slate-900">
                      ${amount.toLocaleString()}
                    </span>
                  </div>
                ))}
              </div>

              <div className="mt-6 pt-4 border-t border-slate-100">
                <div className="text-center">
                  <div className="text-3xl font-bold text-green-600">
                    ${stats.overview.total_revenue.toLocaleString()}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">Total Revenue</div>
                </div>
              </div>
            </div>
          </div>

          {/* Usage Chart + Credit Usage by Category */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            {/* Daily Usage Chart */}
            <div className="bg-white rounded-xl border border-slate-200 p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <TrendingUp size={20} className="text-slate-600" />
                  <h3 className="font-semibold text-slate-900">Daily Usage (30d)</h3>
                </div>
              </div>

              <div className="h-40 flex items-end gap-1">
                {stats.daily_usage_30d.map((day, i) => {
                  const maxCredits = Math.max(...stats.daily_usage_30d.map((d) => d.credits_used));
                  const height = (day.credits_used / maxCredits) * 100;
                  return (
                    <div
                      key={i}
                      className="flex-1 bg-blue-500 hover:bg-blue-600 rounded-t cursor-pointer transition-colors group relative"
                      style={{ height: `${height}%`, minHeight: '4px' }}
                      title={`${day.date}: ${day.credits_used.toLocaleString()} credits`}
                    />
                  );
                })}
              </div>

              <div className="flex justify-between text-xs text-slate-400 mt-2">
                <span>{stats.daily_usage_30d[0]?.date}</span>
                <span>{stats.daily_usage_30d[stats.daily_usage_30d.length - 1]?.date}</span>
              </div>

              <div className="grid grid-cols-3 gap-4 mt-4 pt-4 border-t border-slate-100 text-center">
                <div>
                  <div className="text-lg font-bold text-slate-900">
                    {Math.round(
                      stats.daily_usage_30d.reduce((a, d) => a + d.credits_used, 0) / 30
                    ).toLocaleString()}
                  </div>
                  <div className="text-xs text-slate-500">Avg Daily Credits</div>
                </div>
                <div>
                  <div className="text-lg font-bold text-slate-900">
                    {Math.round(
                      stats.daily_usage_30d.reduce((a, d) => a + d.active_users, 0) / 30
                    )}
                  </div>
                  <div className="text-xs text-slate-500">Avg Daily Users</div>
                </div>
                <div>
                  <div className="text-lg font-bold text-slate-900">
                    {stats.daily_usage_30d.reduce((a, d) => a + d.new_signups, 0)}
                  </div>
                  <div className="text-xs text-slate-500">New Signups</div>
                </div>
              </div>
            </div>

            {/* Credit Usage by Category */}
            <div className="bg-white rounded-xl border border-slate-200 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Database size={20} className="text-slate-600" />
                <h3 className="font-semibold text-slate-900">Credits by Category</h3>
              </div>

              <div className="space-y-3">
                {Object.entries(stats.credit_usage_by_category)
                  .sort(([, a], [, b]) => b - a)
                  .map(([category, credits]) => (
                    <div key={category}>
                      <div className="flex justify-between text-sm mb-1">
                        <span className="text-slate-600 capitalize">
                          {category.replace(/_/g, ' ')}
                        </span>
                        <span className="font-medium text-slate-900">
                          {credits.toLocaleString()}
                        </span>
                      </div>
                      <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-blue-500 to-purple-500 rounded-full"
                          style={{ width: `${(credits / maxCreditsPerCategory) * 100}%` }}
                        />
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          </div>

          {/* Top Tools + Recent Signups + Top Users */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Top Tools */}
            <div className="bg-white rounded-xl border border-slate-200 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Shield size={20} className="text-slate-600" />
                <h3 className="font-semibold text-slate-900">Top Tools (30d)</h3>
              </div>

              <div className="space-y-3">
                {stats.top_tools_30d.slice(0, 8).map((tool, i) => (
                  <div key={tool.tool} className="flex items-center gap-3">
                    <div className="w-6 h-6 rounded-full bg-slate-100 flex items-center justify-center text-xs font-bold text-slate-600">
                      {i + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-slate-900 truncate">
                        {tool.tool.replace(/_/g, ' ')}
                      </div>
                      <div className="text-xs text-slate-500">
                        {tool.usage_count.toLocaleString()} uses
                      </div>
                    </div>
                    <div className="text-sm font-medium text-slate-900">
                      {(tool.credits_used / 1000).toFixed(0)}k
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Recent Signups */}
            <div className="bg-white rounded-xl border border-slate-200 p-6">
              <div className="flex items-center gap-2 mb-4">
                <Users size={20} className="text-slate-600" />
                <h3 className="font-semibold text-slate-900">Recent Signups</h3>
              </div>

              <div className="space-y-3">
                {stats.recent_signups.map((user) => (
                  <div key={user.id} className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-purple-500 flex items-center justify-center text-white text-xs font-bold">
                      {user.email[0].toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-slate-900 truncate">
                        {user.email}
                      </div>
                      <div className="text-xs text-slate-500">
                        {new Date(user.signed_up).toLocaleDateString()}
                      </div>
                    </div>
                    <span
                      className={`px-2 py-1 rounded-full text-xs font-medium ${
                        user.tier === 'enterprise'
                          ? 'bg-amber-100 text-amber-700'
                          : user.tier === 'pro'
                          ? 'bg-purple-100 text-purple-700'
                          : 'bg-slate-100 text-slate-600'
                      }`}
                    >
                      {user.tier}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Top Users */}
            <div className="bg-white rounded-xl border border-slate-200 p-6">
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp size={20} className="text-slate-600" />
                <h3 className="font-semibold text-slate-900">Top Users by Usage</h3>
              </div>

              <div className="space-y-3">
                {stats.top_users_by_usage.map((user, i) => (
                  <div key={user.id} className="flex items-center gap-3">
                    <div className="w-6 h-6 rounded-full bg-gradient-to-br from-amber-400 to-orange-500 flex items-center justify-center text-white text-xs font-bold">
                      {i + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm font-medium text-slate-900 truncate">
                        {user.email}
                      </div>
                      <div className="text-xs text-slate-500">{user.tier}</div>
                    </div>
                    <div className="text-right">
                      <div className="text-sm font-bold text-slate-900">
                        {user.credits_used.toLocaleString()}
                      </div>
                      <div className="text-xs text-slate-400">credits</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Footer */}
          <div className="mt-8 text-center text-sm text-slate-400">
            <p>Aegis Admin Dashboard v1.0</p>
            <p>Data refreshes automatically every 5 minutes</p>
          </div>
        </div>
      </main>
    </div>
  );
}
