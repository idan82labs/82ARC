'use client';

import React, { useState, useEffect } from 'react';
import { Sidebar } from '@/components/dashboard/Sidebar';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import {
  Plus,
  Search,
  Filter,
  Calendar,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  X
} from 'lucide-react';
import Link from 'next/link';

interface Scan {
  id: string;
  agentName: string;
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  severity: 'passed' | 'warning' | 'critical' | null;
  findings: number;
  createdAt: string;
  completedAt?: string;
}

type StatusFilter = 'all' | 'pending' | 'running' | 'completed' | 'failed';
type DateFilter = 'all' | '24h' | '7d' | '30d';

export default function ScansPage() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');
  const [dateFilter, setDateFilter] = useState<DateFilter>('all');
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    fetchScans();
  }, [statusFilter, dateFilter]);

  const fetchScans = async () => {
    try {
      setLoading(true);
      setError(null);

      const params = new URLSearchParams();
      if (statusFilter !== 'all') params.append('status', statusFilter);
      if (dateFilter !== 'all') params.append('date', dateFilter);

      const response = await fetch(`/api/scans?${params.toString()}`);

      if (!response.ok) {
        throw new Error('Failed to fetch scans');
      }

      const result = await response.json();
      setScans(result.scans || []);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      setScans([]);
    } finally {
      setLoading(false);
    }
  };

  const filteredScans = scans.filter((scan) => {
    const matchesSearch =
      scan.agentName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      scan.target.toLowerCase().includes(searchQuery.toLowerCase());

    return matchesSearch;
  });

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'completed':
        return <Badge color="blue">Completed</Badge>;
      case 'running':
        return <Badge color="cyan">Running</Badge>;
      case 'pending':
        return <Badge color="amber">Pending</Badge>;
      case 'failed':
        return <Badge color="red">Failed</Badge>;
      default:
        return <Badge color="blue">{status}</Badge>;
    }
  };

  const getSeverityIcon = (severity: string | null) => {
    switch (severity) {
      case 'passed':
        return <CheckCircle size={20} className="text-green-600" />;
      case 'warning':
        return <AlertTriangle size={20} className="text-amber-600" />;
      case 'critical':
        return <AlertTriangle size={20} className="text-red-600" />;
      default:
        return <Clock size={20} className="text-slate-400" />;
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
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-6xl mx-auto space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-slate-900 mb-2">Security Scans</h1>
              <p className="text-slate-500">Monitor and manage your AI agent security scans</p>
            </div>
            <Button variant="primary">
              <Plus size={16} /> New Scan
            </Button>
          </div>

          {/* Search and Filters */}
          <div className="bg-white border border-slate-200 rounded-xl p-4">
            <div className="flex flex-col md:flex-row gap-4">
              {/* Search */}
              <div className="flex-1 relative">
                <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search by agent name or target..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              {/* Filter Toggle */}
              <Button
                variant="secondary"
                onClick={() => setShowFilters(!showFilters)}
              >
                <Filter size={16} /> Filters
              </Button>
            </div>

            {/* Filter Options */}
            {showFilters && (
              <div className="mt-4 pt-4 border-t border-slate-200 space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Status Filter */}
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-2">
                      Status
                    </label>
                    <div className="flex flex-wrap gap-2">
                      {(['all', 'pending', 'running', 'completed', 'failed'] as StatusFilter[]).map((status) => (
                        <button
                          key={status}
                          onClick={() => setStatusFilter(status)}
                          className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                            statusFilter === status
                              ? 'bg-blue-100 text-blue-700'
                              : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                          }`}
                        >
                          {status.charAt(0).toUpperCase() + status.slice(1)}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Date Filter */}
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-2">
                      Date Range
                    </label>
                    <div className="flex flex-wrap gap-2">
                      {(['all', '24h', '7d', '30d'] as DateFilter[]).map((date) => (
                        <button
                          key={date}
                          onClick={() => setDateFilter(date)}
                          className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                            dateFilter === date
                              ? 'bg-blue-100 text-blue-700'
                              : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                          }`}
                        >
                          {date === 'all' && 'All Time'}
                          {date === '24h' && 'Last 24 Hours'}
                          {date === '7d' && 'Last 7 Days'}
                          {date === '30d' && 'Last 30 Days'}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Clear Filters */}
                {(statusFilter !== 'all' || dateFilter !== 'all' || searchQuery) && (
                  <div className="flex justify-end">
                    <button
                      onClick={() => {
                        setStatusFilter('all');
                        setDateFilter('all');
                        setSearchQuery('');
                      }}
                      className="text-sm text-blue-600 hover:text-blue-700 font-medium flex items-center gap-1"
                    >
                      <X size={14} /> Clear All Filters
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Loading State */}
          {loading && (
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="bg-white border border-slate-200 rounded-xl p-6 animate-pulse"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex-1">
                      <div className="h-5 w-48 bg-slate-200 rounded mb-2"></div>
                      <div className="h-4 w-32 bg-slate-200 rounded"></div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="h-6 w-20 bg-slate-200 rounded"></div>
                      <div className="h-6 w-24 bg-slate-200 rounded"></div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Error State */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-xl p-6">
              <p className="font-semibold text-red-700 mb-2">Error loading scans</p>
              <p className="text-sm text-red-600 mb-4">{error}</p>
              <Button variant="secondary" onClick={fetchScans}>
                Retry
              </Button>
            </div>
          )}

          {/* Empty State */}
          {!loading && !error && filteredScans.length === 0 && !searchQuery && (
            <div className="bg-white border-2 border-dashed border-slate-200 rounded-xl p-12 text-center">
              <div className="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <Shield size={32} className="text-slate-400" />
              </div>
              <h3 className="text-lg font-semibold text-slate-900 mb-2">No scans yet</h3>
              <p className="text-slate-500 mb-6 max-w-sm mx-auto">
                Start protecting your AI agents by running your first security scan.
              </p>
              <Button variant="primary">
                <Plus size={16} /> Run Your First Scan
              </Button>
            </div>
          )}

          {/* No Results State */}
          {!loading && !error && filteredScans.length === 0 && searchQuery && (
            <div className="bg-white border border-slate-200 rounded-xl p-12 text-center">
              <Search size={48} className="text-slate-300 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-slate-900 mb-2">No scans found</h3>
              <p className="text-slate-500 mb-6">
                No scans match your search criteria. Try adjusting your filters.
              </p>
              <Button
                variant="secondary"
                onClick={() => {
                  setSearchQuery('');
                  setStatusFilter('all');
                  setDateFilter('all');
                }}
              >
                Clear Filters
              </Button>
            </div>
          )}

          {/* Scans List */}
          {!loading && !error && filteredScans.length > 0 && (
            <>
              <div className="flex items-center justify-between text-sm text-slate-600">
                <p>Showing {filteredScans.length} scan{filteredScans.length !== 1 ? 's' : ''}</p>
              </div>

              <div className="space-y-3">
                {filteredScans.map((scan) => (
                  <Link key={scan.id} href={`/dashboard/scans/${scan.id}`}>
                    <div className="bg-white border border-slate-200 rounded-xl p-6 hover:border-blue-200 hover:bg-blue-50/30 transition-all cursor-pointer">
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 bg-slate-100 rounded-lg flex items-center justify-center">
                            {getSeverityIcon(scan.severity)}
                          </div>
                          <div>
                            <h3 className="font-semibold text-slate-900">{scan.agentName}</h3>
                            <p className="text-sm text-slate-500">Target: {scan.target}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-4">
                          {getStatusBadge(scan.status)}
                          {scan.status === 'completed' && scan.findings !== undefined && (
                            <div className="text-right">
                              <p className="text-sm font-medium text-slate-900">
                                {scan.findings} finding{scan.findings !== 1 ? 's' : ''}
                              </p>
                            </div>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-xs text-slate-500">
                        <div className="flex items-center gap-4">
                          <span className="flex items-center gap-1">
                            <Calendar size={12} />
                            Started {formatDate(scan.createdAt)}
                          </span>
                          {scan.completedAt && (
                            <span className="flex items-center gap-1">
                              <Clock size={12} />
                              Completed {formatDate(scan.completedAt)}
                            </span>
                          )}
                        </div>
                        <span className="text-blue-600 font-medium">View Details →</span>
                      </div>
                    </div>
                  </Link>
                ))}
              </div>
            </>
          )}
        </div>
      </main>
    </div>
  );
}
