import React from 'react';
import { Sidebar } from '@/components/dashboard/Sidebar';

export default function BillingLoading() {
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-4xl mx-auto">
          {/* Header Skeleton */}
          <div className="mb-8 animate-pulse">
            <div className="h-8 bg-slate-200 rounded-lg w-36 mb-2"></div>
            <div className="h-5 bg-slate-200 rounded-lg w-80"></div>
          </div>

          {/* Current Plan Skeleton */}
          <div className="bg-white rounded-2xl p-6 border border-slate-200 mb-6 animate-pulse">
            <div className="h-6 bg-slate-200 rounded w-32 mb-6"></div>
            <div className="grid md:grid-cols-2 gap-6">
              <div className="space-y-3">
                <div className="h-4 bg-slate-200 rounded w-24"></div>
                <div className="h-8 bg-slate-200 rounded w-40"></div>
              </div>
              <div className="space-y-3">
                <div className="h-4 bg-slate-200 rounded w-32"></div>
                <div className="h-8 bg-slate-200 rounded w-36"></div>
              </div>
            </div>
          </div>

          {/* Credit Packages Skeleton */}
          <div className="bg-white rounded-2xl p-6 border border-slate-200 mb-6 animate-pulse">
            <div className="h-6 bg-slate-200 rounded w-40 mb-6"></div>
            <div className="grid md:grid-cols-3 gap-4">
              {[1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="border border-slate-200 rounded-xl p-6 space-y-4"
                >
                  <div className="h-8 bg-slate-200 rounded w-24"></div>
                  <div className="h-10 bg-slate-200 rounded w-32"></div>
                  <div className="h-4 bg-slate-200 rounded w-full"></div>
                  <div className="h-10 bg-blue-200 rounded-lg w-full"></div>
                </div>
              ))}
            </div>
          </div>

          {/* Payment History Skeleton */}
          <div className="bg-white rounded-2xl p-6 border border-slate-200 animate-pulse">
            <div className="h-6 bg-slate-200 rounded w-40 mb-6"></div>
            <div className="space-y-3">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="flex items-center justify-between p-4 border border-slate-100 rounded-lg">
                  <div className="flex-1 space-y-2">
                    <div className="h-4 bg-slate-200 rounded w-32"></div>
                    <div className="h-3 bg-slate-200 rounded w-24"></div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="h-4 bg-slate-200 rounded w-20"></div>
                    <div className="h-6 bg-slate-200 rounded w-16"></div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
