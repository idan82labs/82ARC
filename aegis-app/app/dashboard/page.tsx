'use client';

import React from 'react';
import { Sidebar } from '@/components/dashboard/Sidebar';
import { CreditDisplay } from '@/components/dashboard/CreditDisplay';
import { UsageChart } from '@/components/dashboard/UsageChart';
import { Shield, TrendingUp, AlertTriangle } from 'lucide-react';

export default function DashboardPage() {
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-6xl mx-auto space-y-8">
          <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">Dashboard</h1>
            <p className="text-slate-500">Monitor your AI agent security posture</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <CreditDisplay credits={2500} onPurchase={() => {}} />

            <div className="bg-white rounded-2xl p-6 border border-slate-200">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-green-100 rounded-lg flex items-center justify-center">
                  <Shield size={20} className="text-green-600" />
                </div>
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-wider">Scans Run</p>
                  <p className="text-3xl font-bold text-slate-900">47</p>
                </div>
              </div>
              <p className="text-sm text-slate-500">12 this month</p>
            </div>

            <div className="bg-white rounded-2xl p-6 border border-slate-200">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 bg-amber-100 rounded-lg flex items-center justify-center">
                  <AlertTriangle size={20} className="text-amber-600" />
                </div>
                <div>
                  <p className="text-xs text-slate-500 uppercase tracking-wider">
                    Active Findings
                  </p>
                  <p className="text-3xl font-bold text-slate-900">3</p>
                </div>
              </div>
              <p className="text-sm text-slate-500">1 critical, 2 high</p>
            </div>
          </div>

          <UsageChart />

          <div className="bg-white rounded-2xl p-6 border border-slate-200">
            <h3 className="font-bold text-slate-900 mb-4">Recent Scans</h3>
            <div className="space-y-3">
              {[
                {
                  agent: 'Customer Support Bot',
                  date: '2 hours ago',
                  status: 'Passed',
                  findings: 0,
                },
                { agent: 'Sales Assistant', date: '1 day ago', status: 'Warning', findings: 2 },
                {
                  agent: 'Data Analyst Agent',
                  date: '3 days ago',
                  status: 'Critical',
                  findings: 1,
                },
              ].map((scan, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between p-4 border border-slate-100 rounded-lg hover:bg-slate-50 transition-colors cursor-pointer"
                >
                  <div>
                    <p className="font-medium text-slate-900">{scan.agent}</p>
                    <p className="text-sm text-slate-500">{scan.date}</p>
                  </div>
                  <div className="flex items-center gap-4">
                    <span className="text-sm text-slate-600">
                      {scan.findings} finding{scan.findings !== 1 ? 's' : ''}
                    </span>
                    <span
                      className={`px-3 py-1 rounded-full text-xs font-medium ${
                        scan.status === 'Passed'
                          ? 'bg-green-100 text-green-700'
                          : scan.status === 'Warning'
                          ? 'bg-amber-100 text-amber-700'
                          : 'bg-red-100 text-red-700'
                      }`}
                    >
                      {scan.status}
                    </span>
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
