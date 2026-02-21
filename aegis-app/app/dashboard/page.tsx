'use client';

import React, { useState, useEffect } from 'react';
import { Sidebar } from '@/components/dashboard/Sidebar';
import { CreditDisplay } from '@/components/dashboard/CreditDisplay';
import { UsageChart } from '@/components/dashboard/UsageChart';
import { Shield, AlertTriangle, Key, PlayCircle, BookOpen, Sparkles } from 'lucide-react';
import { Button } from '@/components/ui/Button';
import Link from 'next/link';

interface DashboardData {
  scansRun: number;
  scansThisMonth: number;
  activeFindings: number;
  findingsBreakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  recentScans: Array<{
    id: string;
    agent: string;
    date: string;
    status: 'Passed' | 'Warning' | 'Critical';
    findings: number;
  }>;
  isNewUser: boolean;
}

export default function DashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch('/api/dashboard');

      if (!response.ok) {
        throw new Error('Failed to fetch dashboard data');
      }

      const result = await response.json();
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Passed':
        return 'bg-green-100 text-green-700';
      case 'Warning':
        return 'bg-amber-100 text-amber-700';
      case 'Critical':
        return 'bg-red-100 text-red-700';
      default:
        return 'bg-slate-100 text-slate-700';
    }
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);

    if (diffMins < 60) return `${diffMins} minute${diffMins !== 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ago`;
    if (diffDays < 30) return `${diffDays} day${diffDays !== 1 ? 's' : ''} ago`;
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  };

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-6xl mx-auto space-y-8">
          <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">Dashboard</h1>
            <p className="text-slate-500">Monitor your AI agent security posture</p>
          </div>

          {loading && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="bg-white rounded-2xl p-6 border border-slate-200 animate-pulse">
                    <div className="flex items-center gap-3 mb-4">
                      <div className="w-10 h-10 bg-slate-200 rounded-lg"></div>
                      <div className="flex-1">
                        <div className="h-3 w-24 bg-slate-200 rounded mb-2"></div>
                        <div className="h-8 w-16 bg-slate-200 rounded"></div>
                      </div>
                    </div>
                    <div className="h-4 w-32 bg-slate-200 rounded"></div>
                  </div>
                ))}
              </div>
              <div className="bg-white rounded-2xl p-6 border border-slate-200 h-64 animate-pulse">
                <div className="h-6 w-32 bg-slate-200 rounded mb-6"></div>
                <div className="h-40 bg-slate-200 rounded"></div>
              </div>
            </>
          )}

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-xl p-6">
              <p className="font-semibold text-red-700 mb-2">Error loading dashboard</p>
              <p className="text-sm text-red-600 mb-4">{error}</p>
              <Button variant="secondary" onClick={fetchDashboardData}>
                Retry
              </Button>
            </div>
          )}

          {!loading && !error && data?.isNewUser && (
            <div className="bg-gradient-to-br from-blue-50 to-indigo-50 border-2 border-blue-200 rounded-2xl p-8">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-12 h-12 bg-blue-500 rounded-full flex items-center justify-center">
                  <Sparkles size={24} className="text-white" />
                </div>
                <div>
                  <h2 className="text-2xl font-bold text-slate-900">Welcome to AEGIS!</h2>
                  <p className="text-slate-600">Get started with AI agent security in minutes</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                <div className="bg-white rounded-xl p-6 border border-slate-200">
                  <div className="w-10 h-10 bg-blue-100 rounded-lg flex items-center justify-center mb-4">
                    <Key size={20} className="text-blue-600" />
                  </div>
                  <h3 className="font-semibold text-slate-900 mb-2">1. Create API Key</h3>
                  <p className="text-sm text-slate-600 mb-4">
                    Generate your first API key to integrate AEGIS with your agents
                  </p>
                  <Link href="/dashboard/api-keys">
                    <Button variant="secondary" className="w-full">
                      Create Key
                    </Button>
                  </Link>
                </div>

                <div className="bg-white rounded-xl p-6 border border-slate-200">
                  <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center mb-4">
                    <PlayCircle size={20} className="text-green-600" />
                  </div>
                  <h3 className="font-semibold text-slate-900 mb-2">2. Run First Scan</h3>
                  <p className="text-sm text-slate-600 mb-4">
                    Start scanning your AI agents for security vulnerabilities
                  </p>
                  <Link href="/dashboard/scans">
                    <Button variant="secondary" className="w-full">
                      New Scan
                    </Button>
                  </Link>
                </div>

                <div className="bg-white rounded-xl p-6 border border-slate-200">
                  <div className="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center mb-4">
                    <BookOpen size={20} className="text-purple-600" />
                  </div>
                  <h3 className="font-semibold text-slate-900 mb-2">3. View Docs</h3>
                  <p className="text-sm text-slate-600 mb-4">
                    Learn best practices for AI agent security testing
                  </p>
                  <a href="/docs" target="_blank" rel="noopener noreferrer">
                    <Button variant="secondary" className="w-full">
                      Read Docs
                    </Button>
                  </a>
                </div>
              </div>
            </div>
          )}

          {!loading && !error && data && !data.isNewUser && (
            <>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <CreditDisplay />

                <div className="bg-white rounded-2xl p-6 border border-slate-200">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
                      <Shield size={20} className="text-green-600" />
                    </div>
                    <div>
                      <p className="text-xs text-slate-500 uppercase tracking-wider">Scans Run</p>
                      <p className="text-3xl font-bold text-slate-900">{data.scansRun}</p>
                    </div>
                  </div>
                  <p className="text-sm text-slate-500">{data.scansThisMonth} this month</p>
                </div>

                <div className="bg-white rounded-2xl p-6 border border-slate-200">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-10 h-10 bg-amber-100 rounded-lg flex items-center justify-center">
                      <AlertTriangle size={20} className="text-amber-600" />
                    </div>
                    <div>
                      <p className="text-xs text-slate-500 uppercase tracking-wider">
                        Active Findings
                      </p>
                      <p className="text-3xl font-bold text-slate-900">{data.activeFindings}</p>
                    </div>
                  </div>
                  <p className="text-sm text-slate-500">
                    {data.findingsBreakdown.critical} critical, {data.findingsBreakdown.high} high
                  </p>
                </div>
              </div>

              <UsageChart />

              <div className="bg-white rounded-2xl p-6 border border-slate-200">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-bold text-slate-900">Recent Scans</h3>
                  <Link href="/dashboard/scans">
                    <Button variant="smallSecondary">View All</Button>
                  </Link>
                </div>

                {data.recentScans.length === 0 ? (
                  <div className="text-center py-12">
                    <Shield size={48} className="text-slate-300 mx-auto mb-4" />
                    <p className="text-slate-500 mb-2">No scans yet</p>
                    <Link href="/dashboard/scans">
                      <Button variant="primary">Run Your First Scan</Button>
                    </Link>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {data.recentScans.map((scan) => (
                      <Link key={scan.id} href={`/dashboard/scans/${scan.id}`}>
                        <div className="flex items-center justify-between p-4 border border-slate-100 rounded-lg hover:bg-slate-50 transition-colors cursor-pointer">
                          <div>
                            <p className="font-medium text-slate-900">{scan.agent}</p>
                            <p className="text-sm text-slate-500">{formatDate(scan.date)}</p>
                          </div>
                          <div className="flex items-center gap-4">
                            <span className="text-sm text-slate-600">
                              {scan.findings} finding{scan.findings !== 1 ? 's' : ''}
                            </span>
                            <span
                              className={`px-3 py-1 rounded-full text-xs font-medium ${getStatusColor(
                                scan.status
                              )}`}
                            >
                              {scan.status}
                            </span>
                          </div>
                        </div>
                      </Link>
                    ))}
                  </div>
                )}
              </div>

              {data.recentScans.length > 0 && (
                <div className="bg-gradient-to-br from-slate-50 to-slate-100 border border-slate-200 rounded-2xl p-6">
                  <h3 className="font-bold text-slate-900 mb-4">Quick Actions</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <Link href="/dashboard/api-keys">
                      <button className="w-full bg-white border border-slate-200 rounded-xl p-4 hover:border-blue-300 hover:bg-blue-50 transition-all text-left group">
                        <Key size={20} className="text-blue-600 mb-2" />
                        <p className="font-semibold text-slate-900 mb-1">Create API Key</p>
                        <p className="text-sm text-slate-500">Generate a new API key</p>
                      </button>
                    </Link>
                    <Link href="/dashboard/scans">
                      <button className="w-full bg-white border border-slate-200 rounded-xl p-4 hover:border-green-300 hover:bg-green-50 transition-all text-left group">
                        <PlayCircle size={20} className="text-green-600 mb-2" />
                        <p className="font-semibold text-slate-900 mb-1">Run New Scan</p>
                        <p className="text-sm text-slate-500">Start a security scan</p>
                      </button>
                    </Link>
                    <a href="/docs" target="_blank" rel="noopener noreferrer">
                      <button className="w-full bg-white border border-slate-200 rounded-xl p-4 hover:border-purple-300 hover:bg-purple-50 transition-all text-left group">
                        <BookOpen size={20} className="text-purple-600 mb-2" />
                        <p className="font-semibold text-slate-900 mb-1">View Documentation</p>
                        <p className="text-sm text-slate-500">Learn more about AEGIS</p>
                      </button>
                    </a>
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </main>
    </div>
  );
}
