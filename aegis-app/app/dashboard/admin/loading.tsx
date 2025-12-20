import { Sidebar } from '@/components/dashboard/Sidebar';

export default function AdminLoading() {
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-7xl mx-auto">
          {/* Header skeleton */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <div className="h-9 w-64 bg-slate-200 rounded-lg animate-pulse mb-2" />
              <div className="h-5 w-48 bg-slate-200 rounded animate-pulse" />
            </div>
            <div className="flex gap-3">
              <div className="h-10 w-24 bg-slate-200 rounded-lg animate-pulse" />
              <div className="h-10 w-32 bg-slate-200 rounded-lg animate-pulse" />
            </div>
          </div>

          {/* Stats cards skeleton */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="bg-white rounded-xl border border-slate-200 p-6">
                <div className="flex items-start justify-between mb-4">
                  <div className="w-12 h-12 bg-slate-100 rounded-lg animate-pulse" />
                  <div className="w-12 h-5 bg-slate-100 rounded animate-pulse" />
                </div>
                <div className="h-8 w-24 bg-slate-200 rounded animate-pulse mb-2" />
                <div className="h-4 w-32 bg-slate-100 rounded animate-pulse" />
              </div>
            ))}
          </div>

          {/* Charts skeleton */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="bg-white rounded-xl border border-slate-200 p-6">
                <div className="h-6 w-32 bg-slate-200 rounded animate-pulse mb-4" />
                <div className="space-y-3">
                  {[...Array(4)].map((_, j) => (
                    <div key={j} className="flex items-center gap-3">
                      <div className="w-full h-4 bg-slate-100 rounded animate-pulse" />
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Tables skeleton */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {[...Array(2)].map((_, i) => (
              <div key={i} className="bg-white rounded-xl border border-slate-200 p-6">
                <div className="h-6 w-40 bg-slate-200 rounded animate-pulse mb-4" />
                <div className="h-40 bg-slate-50 rounded-lg animate-pulse" />
              </div>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
