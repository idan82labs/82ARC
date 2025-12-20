'use client';

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Download } from 'lucide-react';
import { Button } from '@/components/ui/Button';

interface UsageData {
  date: string;
  scans: number;
  credits: number;
}

type DateRange = '7d' | '30d' | '90d';

export const UsageChart: React.FC = () => {
  const [data, setData] = useState<UsageData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [dateRange, setDateRange] = useState<DateRange>('7d');
  const [creditsUsed, setCreditsUsed] = useState(0);
  const [creditsRemaining, setCreditsRemaining] = useState(0);

  useEffect(() => {
    fetchUsageData();
  }, [dateRange]);

  const fetchUsageData = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch(`/api/usage?range=${dateRange}`);

      if (!response.ok) {
        throw new Error('Failed to fetch usage data');
      }

      const result = await response.json();
      setData(result.data || []);
      setCreditsUsed(result.creditsUsed || 0);
      setCreditsRemaining(result.creditsRemaining || 0);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
      setData([]);
    } finally {
      setLoading(false);
    }
  };

  const exportToCSV = () => {
    const headers = ['Date', 'Scans', 'Credits Used'];
    const rows = data.map((item) => [item.date, item.scans, item.credits]);
    const csv = [headers, ...rows].map((row) => row.join(',')).join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `usage-${dateRange}-${new Date().toISOString().split('T')[0]}.csv`;
    link.click();
    window.URL.revokeObjectURL(url);
  };

  const maxScans = data.length > 0 ? Math.max(...data.map((d) => d.scans)) : 1;

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <div className="bg-white border border-slate-200 rounded-xl p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="font-bold text-slate-900">Usage Overview</h3>
          <p className="text-sm text-slate-500 mt-1">
            {creditsUsed.toLocaleString()} credits used • {creditsRemaining.toLocaleString()} remaining
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex gap-2">
            {(['7d', '30d', '90d'] as DateRange[]).map((range) => (
              <button
                key={range}
                onClick={() => setDateRange(range)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  dateRange === range
                    ? 'bg-blue-100 text-blue-700'
                    : 'text-slate-600 hover:bg-slate-100'
                }`}
              >
                {range === '7d' && '7 Days'}
                {range === '30d' && '30 Days'}
                {range === '90d' && '90 Days'}
              </button>
            ))}
          </div>
          <Button
            variant="smallSecondary"
            onClick={exportToCSV}
            disabled={loading || data.length === 0}
          >
            <Download size={14} /> CSV
          </Button>
        </div>
      </div>

      {loading && (
        <div className="h-48 flex items-center justify-center">
          <div className="animate-pulse space-y-4 w-full">
            <div className="flex items-end justify-between gap-2 h-40">
              {[...Array(dateRange === '7d' ? 7 : dateRange === '30d' ? 15 : 12)].map((_, i) => (
                <div key={i} className="flex-1 flex flex-col items-center gap-2">
                  <div className="w-full bg-slate-200 rounded-t-lg" style={{ height: `${Math.random() * 100}%` }}></div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="h-48 flex items-center justify-center">
          <div className="text-center">
            <p className="text-red-600 font-semibold mb-2">Error loading usage data</p>
            <p className="text-sm text-slate-500 mb-4">{error}</p>
            <Button variant="secondary" onClick={fetchUsageData}>
              Retry
            </Button>
          </div>
        </div>
      )}

      {!loading && !error && data.length === 0 && (
        <div className="h-48 flex items-center justify-center">
          <div className="text-center text-slate-500">
            <p className="font-semibold mb-1">No usage data available</p>
            <p className="text-sm">Run your first scan to see usage statistics</p>
          </div>
        </div>
      )}

      {!loading && !error && data.length > 0 && (
        <div className="flex items-end justify-between gap-2 h-48">
          {data.map((item, i) => {
            const height = maxScans > 0 ? (item.scans / maxScans) * 100 : 0;
            return (
              <div key={i} className="flex-1 flex flex-col items-center gap-2">
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: `${height}%` }}
                  transition={{ delay: i * 0.05, duration: 0.5 }}
                  className="w-full bg-blue-500 rounded-t-lg relative group cursor-pointer hover:bg-blue-600 transition-colors min-h-[4px]"
                >
                  <div className="absolute -top-16 left-1/2 -translate-x-1/2 bg-slate-900 text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap z-10">
                    <div className="font-semibold">{formatDate(item.date)}</div>
                    {item.scans} scan{item.scans !== 1 ? 's' : ''}
                    <br />
                    {item.credits.toLocaleString()} credits
                  </div>
                </motion.div>
                <span className="text-xs text-slate-500">{formatDate(item.date).split(' ')[1]}</span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
