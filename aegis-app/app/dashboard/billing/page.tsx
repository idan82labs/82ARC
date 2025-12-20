'use client';

import React from 'react';
import { Sidebar } from '@/components/dashboard/Sidebar';
import { CreditDisplay } from '@/components/dashboard/CreditDisplay';
import { Button } from '@/components/ui/Button';

export default function BillingPage() {
  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-4xl mx-auto space-y-8">
          <div>
            <h1 className="text-3xl font-bold text-slate-900 mb-2">Billing & Credits</h1>
            <p className="text-slate-500">Manage your subscription and purchase credits</p>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            <CreditDisplay credits={2500} onPurchase={() => {}} />

            <div className="bg-white rounded-2xl p-6 border border-slate-200">
              <h3 className="font-bold text-slate-900 mb-4">Current Plan</h3>
              <div className="space-y-3">
                <div>
                  <p className="text-2xl font-bold text-slate-900">Continuous</p>
                  <p className="text-sm text-slate-500">Quarterly billing</p>
                </div>
                <Button variant="secondary" className="w-full">
                  Upgrade Plan
                </Button>
              </div>
            </div>
          </div>

          <div className="bg-white rounded-2xl p-6 border border-slate-200">
            <h3 className="font-bold text-slate-900 mb-6">Credit Packages</h3>
            <div className="grid md:grid-cols-3 gap-4">
              {[
                { credits: 1000, price: 99, bonus: 0 },
                { credits: 5000, price: 449, bonus: 500, popular: true },
                { credits: 10000, price: 849, bonus: 1500 },
              ].map((pkg, i) => (
                <div
                  key={i}
                  className={`p-6 rounded-xl border-2 ${
                    pkg.popular ? 'border-blue-500 bg-blue-50/30' : 'border-slate-200 bg-white'
                  }`}
                >
                  {pkg.popular && (
                    <span className="text-xs bg-blue-500 text-white px-2 py-1 rounded-full font-medium">
                      Popular
                    </span>
                  )}
                  <p className="text-3xl font-bold text-slate-900 mt-3">
                    {pkg.credits.toLocaleString()}
                  </p>
                  <p className="text-sm text-slate-500 mb-1">credits</p>
                  {pkg.bonus > 0 && (
                    <p className="text-xs text-green-600 font-medium mb-3">
                      +{pkg.bonus} bonus credits
                    </p>
                  )}
                  <p className="text-2xl font-bold text-slate-900 mb-4">${pkg.price}</p>
                  <Button
                    variant={pkg.popular ? 'primary' : 'secondary'}
                    className="w-full"
                  >
                    Purchase
                  </Button>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-white rounded-2xl p-6 border border-slate-200">
            <h3 className="font-bold text-slate-900 mb-4">Payment History</h3>
            <div className="space-y-3">
              {[
                { date: 'Dec 1, 2024', description: '1000 Credits', amount: 99 },
                { date: 'Nov 1, 2024', description: 'Continuous Plan', amount: 449 },
              ].map((payment, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between p-4 border border-slate-100 rounded-lg"
                >
                  <div>
                    <p className="font-medium text-slate-900">{payment.description}</p>
                    <p className="text-sm text-slate-500">{payment.date}</p>
                  </div>
                  <p className="font-bold text-slate-900">${payment.amount}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
