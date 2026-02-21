'use client';

import React from 'react';
import Link from 'next/link';
import { motion } from 'framer-motion';
import { Home, Search, Shield } from 'lucide-react';
import { Button } from '@/components/ui/Button';

export default function NotFound() {
  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center px-6">
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
              <div className="w-24 h-24 bg-blue-100 rounded-full flex items-center justify-center">
                <Shield size={48} className="text-blue-600" />
              </div>
              <motion.div
                animate={{ scale: [1, 1.2, 1] }}
                transition={{ duration: 2, repeat: Infinity }}
                className="absolute inset-0 bg-blue-200 rounded-full opacity-20"
              />
            </div>
          </motion.div>

          {/* Error Code */}
          <div>
            <motion.h1
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.3 }}
              className="text-8xl font-extrabold text-slate-900 mb-4"
            >
              404
            </motion.h1>
            <motion.h2
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.4 }}
              className="text-3xl font-bold text-slate-900 mb-4"
            >
              Page Not Found
            </motion.h2>
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.5 }}
              className="text-lg text-slate-500 max-w-md mx-auto"
            >
              The page you're looking for doesn't exist or has been moved. Let's get you back on
              track.
            </motion.p>
          </div>

          {/* Actions */}
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.6 }}
            className="flex flex-col sm:flex-row gap-4 justify-center"
          >
            <Link href="/">
              <Button variant="primary">
                <Home size={18} />
                Back to Home
              </Button>
            </Link>
            <Link href="/dashboard">
              <Button variant="secondary">
                <Shield size={18} />
                Go to Dashboard
              </Button>
            </Link>
          </motion.div>

          {/* Helpful Links */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.7 }}
            className="pt-8 border-t border-slate-200"
          >
            <p className="text-sm text-slate-400 mb-4 uppercase tracking-wider font-semibold">
              Popular Pages
            </p>
            <div className="flex flex-wrap justify-center gap-4 text-sm">
              <Link
                href="/pricing"
                className="text-blue-600 hover:text-blue-700 hover:underline font-medium"
              >
                Pricing
              </Link>
              <span className="text-slate-300">•</span>
              <Link
                href="/docs"
                className="text-blue-600 hover:text-blue-700 hover:underline font-medium"
              >
                Documentation
              </Link>
              <span className="text-slate-300">•</span>
              <Link
                href="/getting-started"
                className="text-blue-600 hover:text-blue-700 hover:underline font-medium"
              >
                Getting Started
              </Link>
              <span className="text-slate-300">•</span>
              <Link
                href="/contact"
                className="text-blue-600 hover:text-blue-700 hover:underline font-medium"
              >
                Contact
              </Link>
            </div>
          </motion.div>
        </motion.div>
      </div>
    </div>
  );
}
