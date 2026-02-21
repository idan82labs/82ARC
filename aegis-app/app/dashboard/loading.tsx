import React from 'react';
import { Sidebar } from '@/components/dashboard/Sidebar';

export default function DashboardLoading() {
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-6xl mx-auto space-y-8">
          {/* Header Skeleton */}
          <div className="animate-pulse">
            <div className="h-8 bg-slate-200 rounded-lg w-48 mb-2"></div>
            <div className="h-5 bg-slate-200 rounded-lg w-64"></div>
          </div>

          {/* Stats Cards Skeleton */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {[1, 2, 3].map((i) => (
              <div key={i} className="bg-white rounded-2xl p-6 border border-slate-200 animate-pulse">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-slate-200 rounded-lg"></div>
                  <div className="flex-1 space-y-2">
                    <div className="h-3 bg-slate-200 rounded w-20"></div>
                    <div className="h-8 bg-slate-200 rounded w-16"></div>
                  </div>
                </div>
                <div className="h-4 bg-slate-200 rounded w-24"></div>
              </div>
            ))}
          </div>

          {/* Usage Chart Skeleton */}
          <div className="bg-white rounded-2xl p-6 border border-slate-200 animate-pulse">
            <div className="h-6 bg-slate-200 rounded-lg w-32 mb-6"></div>
            <div className="h-64 bg-slate-100 rounded-lg"></div>
          </div>

          {/* Recent Scans Skeleton */}
          <div className="bg-white rounded-2xl p-6 border border-slate-200 animate-pulse">
            <div className="h-6 bg-slate-200 rounded-lg w-32 mb-6"></div>
            <div className="space-y-3">
              {[1, 2, 3].map((i) => (
                <div key={i} className="flex items-center justify-between p-4 border border-slate-100 rounded-lg">
                  <div className="flex-1 space-y-2">
                    <div className="h-4 bg-slate-200 rounded w-48"></div>
                    <div className="h-3 bg-slate-200 rounded w-24"></div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="h-4 bg-slate-200 rounded w-20"></div>
                    <div className="h-6 bg-slate-200 rounded-full w-16"></div>
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
