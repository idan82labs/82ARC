'use client';

import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
import { AlertTriangle, RefreshCw, LayoutDashboard } from 'lucide-react';
import Link from 'next/link';
import { Button } from '@/components/ui/Button';
import { Sidebar } from '@/components/dashboard/Sidebar';

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error('Dashboard error:', error);
  }, [error]);

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 flex items-center justify-center p-8">
        <div className="max-w-2xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="space-y-8"
          >
            {/* Icon */}
            <motion.div
              initial={{ scale: 0.8, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ delay: 0.2, duration: 0.5 }}
              className="flex justify-center"
            >
              <div className="relative">
                <div className="w-20 h-20 bg-amber-100 rounded-full flex items-center justify-center">
                  <AlertTriangle size={40} className="text-amber-600" />
                </div>
                <motion.div
                  animate={{ scale: [1, 1.2, 1] }}
                  transition={{ duration: 2, repeat: Infinity }}
                  className="absolute inset-0 bg-amber-200 rounded-full opacity-20"
                />
              </div>
            </motion.div>

            {/* Error Message */}
            <div>
              <motion.h1
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.3 }}
                className="text-2xl font-bold text-slate-900 mb-4"
              >
                Dashboard Error
              </motion.h1>
              <motion.p
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.4 }}
                className="text-lg text-slate-500 max-w-md mx-auto mb-2"
              >
                We couldn't load this dashboard section. Please try again.
              </motion.p>
              {error.digest && (
                <motion.p
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.5 }}
                  className="text-sm text-slate-400 font-mono"
                >
                  Error ID: {error.digest}
                </motion.p>
              )}
            </div>

            {/* Error Details (Development) */}
            {process.env.NODE_ENV === 'development' && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.6 }}
                className="bg-white rounded-xl border border-slate-200 p-6 text-left"
              >
                <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                  Error Details
                </p>
                <p className="text-sm text-red-600 font-mono break-all">{error.message}</p>
              </motion.div>
            )}

            {/* Actions */}
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.7 }}
              className="flex flex-col sm:flex-row gap-4 justify-center"
            >
              <Button variant="primary" onClick={reset}>
                <RefreshCw size={18} />
                Retry
              </Button>
              <Link href="/dashboard">
                <Button variant="secondary">
                  <LayoutDashboard size={18} />
                  Dashboard Home
                </Button>
              </Link>
            </motion.div>
          </motion.div>
        </div>
      </main>
    </div>
  );
}
