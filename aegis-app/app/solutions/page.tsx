'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Briefcase, Stethoscope, Layers } from 'lucide-react';
import { Nav } from '@/components/layout/Nav';
import { Footer } from '@/components/layout/Footer';
import { Badge } from '@/components/ui/Badge';

export default function SolutionsPage() {
  return (
    <>
      <Nav />
      <main className="pt-32 pb-24 max-w-[1120px] mx-auto px-6">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <Badge color="blue">Industry Solutions</Badge>
          <h1 className="text-4xl font-bold text-slate-900 mt-6 mb-6">
            Security for every agent architecture.
          </h1>
          <p className="text-xl text-slate-500">
            Specialized threat models for highly regulated industries.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-8 mb-24">
          {[
            {
              title: 'Fintech',
              icon: Briefcase,
              desc: 'Prevent unauthorized transactions and PII leakage in banking agents.',
              tags: ['Fraud Detection', 'Transaction Auth', 'GLBA Compliance'],
            },
            {
              title: 'Healthcare',
              icon: Stethoscope,
              desc: 'Ensure HIPAA compliance for patient-facing triage and support agents.',
              tags: ['PHI Redaction', 'Medical Advice Safety', 'HIPAA'],
            },
            {
              title: 'Enterprise SaaS',
              icon: Layers,
              desc: 'Secure customer support bots against social engineering and prompt injection.',
              tags: ['Tenant Isolation', 'SQL Injection', 'SOC2'],
            },
          ].map((card, i) => (
            <motion.div
              key={i}
              whileHover={{ y: -5 }}
              className="bg-white p-8 rounded-2xl border border-slate-200 shadow-sm hover:shadow-lg transition-all"
            >
              <div className="w-12 h-12 bg-blue-50 rounded-xl flex items-center justify-center text-blue-600 mb-6">
                <card.icon size={24} />
              </div>
              <h3 className="text-xl font-bold text-slate-900 mb-3">{card.title}</h3>
              <p className="text-slate-500 mb-6">{card.desc}</p>
              <div className="flex flex-wrap gap-2">
                {card.tags.map((tag, t) => (
                  <span
                    key={t}
                    className="px-2 py-1 bg-slate-50 text-slate-600 text-xs font-medium rounded border border-slate-100"
                  >
                    {tag}
                  </span>
                ))}
              </div>
            </motion.div>
          ))}
        </div>

        <div className="bg-slate-900 rounded-3xl p-8 md:p-12 text-white relative overflow-hidden">
          <div className="relative z-10 flex flex-col md:flex-row items-center justify-between gap-8">
            <div className="space-y-4 max-w-xl">
              <h3 className="text-2xl font-bold">Custom Enterprise Solutions</h3>
              <p className="text-slate-300">
                Building a custom foundational model or a complex agentic swarm? We offer bespoke
                red-teaming engagements and on-premise deployment options.
              </p>
            </div>
            <button className="bg-white text-slate-900 px-6 py-3 rounded-lg font-bold hover:bg-slate-100 transition-colors">
              Contact Sales
            </button>
          </div>
          <div className="absolute top-0 right-0 w-64 h-64 bg-blue-600 rounded-full blur-[100px] opacity-20 pointer-events-none"></div>
        </div>
      </main>
      <Footer />
    </>
  );
}
