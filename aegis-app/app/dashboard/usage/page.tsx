'use client';

import React from 'react';
import { Sidebar } from '@/components/dashboard/Sidebar';
import { UsageChart } from '@/components/dashboard/UsageChart';

export default function UsagePage() {
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-4xl mx-auto space-y-8">
          <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">Usage Analytics</h1>
            <p className="text-slate-500">Track your security scanning activity</p>
          </div>

          <UsageChart />

          <div className="bg-white rounded-2xl p-6 border border-slate-200">
            <h3 className="font-bold text-slate-900 mb-4">Detailed Usage Log</h3>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-slate-200">
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">Date</th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">
                      Operation
                    </th>
                    <th className="text-left py-3 px-4 text-sm font-medium text-slate-600">
                      Agent
                    </th>
                    <th className="text-right py-3 px-4 text-sm font-medium text-slate-600">
                      Credits
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {[
                    { date: 'Jan 7, 2024', op: 'Security Scan', agent: 'Support Bot', credits: 30 },
                    { date: 'Jan 7, 2024', op: 'RAG Analysis', agent: 'Sales AI', credits: 50 },
                    { date: 'Jan 6, 2024', op: 'Security Scan', agent: 'Data Agent', credits: 30 },
                  ].map((row, i) => (
                    <tr key={i} className="border-b border-slate-100">
                      <td className="py-3 px-4 text-sm text-slate-600">{row.date}</td>
                      <td className="py-3 px-4 text-sm text-slate-900">{row.op}</td>
                      <td className="py-3 px-4 text-sm text-slate-600">{row.agent}</td>
                      <td className="py-3 px-4 text-sm text-slate-900 text-right font-medium">
                        {row.credits}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
