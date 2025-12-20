import React from 'react';
import { Sidebar } from '@/components/dashboard/Sidebar';

export default function UsageLoading() {
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-6xl mx-auto">
          {/* Header Skeleton */}
          <div className="mb-8 animate-pulse">
            <div className="h-8 bg-slate-200 rounded-lg w-36 mb-2"></div>
            <div className="h-5 bg-slate-200 rounded-lg w-96"></div>
          </div>

          {/* Stats Overview Skeleton */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className="bg-white rounded-2xl p-6 border border-slate-200 animate-pulse">
                <div className="flex items-center gap-3 mb-4">
                  <div className="w-10 h-10 bg-slate-200 rounded-lg"></div>
                  <div className="flex-1 space-y-2">
                    <div className="h-3 bg-slate-200 rounded w-20"></div>
                    <div className="h-8 bg-slate-200 rounded w-16"></div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Usage Chart Skeleton */}
          <div className="bg-white rounded-2xl p-6 border border-slate-200 mb-8 animate-pulse">
            <div className="flex items-center justify-between mb-6">
              <div className="h-6 bg-slate-200 rounded w-40"></div>
              <div className="flex gap-2">
                <div className="h-8 bg-slate-200 rounded w-16"></div>
                <div className="h-8 bg-slate-200 rounded w-16"></div>
                <div className="h-8 bg-slate-200 rounded w-16"></div>
              </div>
            </div>
            <div className="h-80 bg-slate-100 rounded-lg"></div>
          </div>

          {/* Usage by Tool Skeleton */}
          <div className="bg-white rounded-2xl p-6 border border-slate-200 mb-8 animate-pulse">
            <div className="h-6 bg-slate-200 rounded w-40 mb-6"></div>
            <div className="space-y-4">
              {[1, 2, 3, 4, 5].map((i) => (
                <div key={i} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="h-4 bg-slate-200 rounded w-32"></div>
                    <div className="h-4 bg-slate-200 rounded w-20"></div>
                  </div>
                  <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-slate-200 rounded-full"
                      style={{ width: `${Math.random() * 100}%` }}
                    ></div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Recent Activity Skeleton */}
          <div className="bg-white rounded-2xl p-6 border border-slate-200 animate-pulse">
            <div className="h-6 bg-slate-200 rounded w-40 mb-6"></div>
            <div className="space-y-3">
              {[1, 2, 3, 4, 5, 6].map((i) => (
                <div key={i} className="flex items-center justify-between p-4 border border-slate-100 rounded-lg">
                  <div className="flex-1 space-y-2">
                    <div className="h-4 bg-slate-200 rounded w-48"></div>
                    <div className="h-3 bg-slate-200 rounded w-32"></div>
                  </div>
                  <div className="flex items-center gap-4">
                    <div className="h-4 bg-slate-200 rounded w-16"></div>
                    <div className="h-6 bg-slate-200 rounded w-12"></div>
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
