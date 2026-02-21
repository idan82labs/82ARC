import React from 'react';
import { Sidebar } from '@/components/dashboard/Sidebar';

export default function APIKeysLoading() {
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-4xl mx-auto">
          {/* Header Skeleton */}
          <div className="mb-8 animate-pulse">
            <div className="h-8 bg-slate-200 rounded-lg w-40 mb-2"></div>
            <div className="h-5 bg-slate-200 rounded-lg w-72"></div>
          </div>

          {/* API Key Manager Skeleton */}
          <div className="bg-white rounded-2xl p-6 border border-slate-200 animate-pulse space-y-6">
            {/* Header with Create Button */}
            <div className="flex items-center justify-between pb-4 border-b border-slate-100">
              <div className="h-6 bg-slate-200 rounded w-32"></div>
              <div className="h-10 bg-blue-200 rounded-lg w-32"></div>
            </div>

            {/* API Keys List */}
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <div key={i} className="p-4 border border-slate-100 rounded-xl">
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex-1 space-y-2">
                      <div className="h-5 bg-slate-200 rounded w-48"></div>
                      <div className="h-4 bg-slate-200 rounded w-96"></div>
                    </div>
                    <div className="h-8 bg-slate-200 rounded w-16"></div>
                  </div>
                  <div className="flex items-center gap-4 text-sm">
                    <div className="h-3 bg-slate-200 rounded w-32"></div>
                    <div className="h-3 bg-slate-200 rounded w-24"></div>
                  </div>
                </div>
              ))}
            </div>

            {/* Empty State or Info */}
            <div className="text-center py-8">
              <div className="h-12 w-12 bg-slate-200 rounded-full mx-auto mb-4"></div>
              <div className="h-5 bg-slate-200 rounded w-64 mx-auto mb-2"></div>
              <div className="h-4 bg-slate-200 rounded w-96 mx-auto"></div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
