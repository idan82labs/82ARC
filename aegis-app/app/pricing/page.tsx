'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Check } from 'lucide-react';
import Link from 'next/link';
import { Nav } from '@/components/layout/Nav';
import { Footer } from '@/components/layout/Footer';
import { Button } from '@/components/ui/Button';

export default function PricingPage() {
  return (
    <>
      <Nav />
      <main className="pt-32 pb-24 max-w-[1120px] mx-auto px-6">
        <div className="text-center mb-16">
          <h1 className="text-4xl font-bold text-slate-900 mb-4">Simple, transparent pricing.</h1>
          <p className="text-slate-500">
            Choose the engagement model that fits your development cycle.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-8">
          {[
            {
              name: 'Spot Assessment',
              price: 'One-time',
              desc: 'For launching a single new agent.',
              features: ['1 Agent Scope', '2 Weeks Duration', 'Full PDF Report', 'Regression Pack'],
            },
            {
              name: 'Continuous',
              price: 'Quarterly',
              desc: 'For teams shipping updates often.',
              features: [
                'Up to 5 Agents',
                'Continuous Scanning',
                'Monthly Readouts',
                'Dedicated Slack Channel',
                'Retesting included',
              ],
              highlight: true,
            },
            {
              name: 'Enterprise',
              price: 'Custom',
              desc: 'For platform-level coverage.',
              features: [
                'Unlimited Agents',
                'Custom Threat Modeling',
                'On-prem execution option',
                'SLA Guarantees',
              ],
            },
          ].map((plan, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.1 }}
              className={`p-8 rounded-2xl border ${
                plan.highlight
                  ? 'border-blue-200 bg-blue-50/30 ring-1 ring-blue-100'
                  : 'border-slate-200 bg-white'
              }`}
            >
              <h3 className="font-bold text-slate-900 text-lg mb-2">{plan.name}</h3>
              <div className="text-3xl font-bold text-slate-900 mb-4">{plan.price}</div>
              <p className="text-slate-500 text-sm mb-8">{plan.desc}</p>
              <Link href="/contact">
                <Button
                  variant={plan.highlight ? 'primary' : 'secondary'}
                  className="w-full mb-8"
                >
                  Talk to Sales
                </Button>
              </Link>
              <ul className="space-y-3">
                {plan.features.map((f, idx) => (
                  <li key={idx} className="flex items-center gap-2 text-sm text-slate-700">
                    <Check size={16} className="text-blue-600" /> {f}
                  </li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>
      </main>
      <Footer />
    </>
  );
}
