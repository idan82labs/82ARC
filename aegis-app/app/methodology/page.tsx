'use client';

import React from 'react';
import { motion } from 'framer-motion';
import { Search, Target, Terminal, FileText, Check } from 'lucide-react';
import { Nav } from '@/components/layout/Nav';
import { Footer } from '@/components/layout/Footer';
import { Badge } from '@/components/ui/Badge';
import {
  ScanVisual,
  ThreatVisual,
  AttackVisual,
  ReportVisual,
} from '@/components/home/MethodologyVisuals';

export default function MethodologyPage() {
  const steps = [
    {
      title: '1. Discovery & Mapping',
      desc: "We analyze your system prompts, RAG sources, and tool definitions to map the attack surface. We identify 'crown jewel' assets and unauthorized states.",
      icon: Search,
      details: ['System Prompt Analysis', 'Tool Permission Auditing', 'Data Classification'],
      Visual: ScanVisual,
    },
    {
      title: '2. Threat Modeling',
      desc: "We develop specific attack scenarios based on your agent's business logic. This isn't just generic fuzzing; it's targeted manipulation.",
      icon: Target,
      details: ['Logic Flaw Identification', 'Privilege Escalation Paths', 'PII Extraction Routes'],
      Visual: ThreatVisual,
    },
    {
      title: '3. Red Teaming',
      desc: 'Our automated engines launch thousands of probes, followed by expert human red teamers who attempt complex, multi-turn exploits.',
      icon: Terminal,
      details: ['Automated Probe Injection', 'Manual Jailbreaking', 'Adversarial Examples'],
      Visual: AttackVisual,
    },
    {
      title: '4. Reporting & Regression',
      desc: 'You get a prioritized list of findings. Once patched, we integrate regression tests into your CI/CD to prevent recurrence.',
      icon: FileText,
      details: ['Detailed Remediation Guide', 'Regression Test Suite', 'Executive Summary'],
      Visual: ReportVisual,
    },
  ];

  return (
    <>
      <Nav />
      <main className="pt-32 pb-24 max-w-[1120px] mx-auto px-6">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <Badge color="blue">Our Process</Badge>
          <h1 className="text-4xl font-bold text-slate-900 mt-6 mb-6">
            How we break agents to build them stronger.
          </h1>
          <p className="text-xl text-slate-500">
            A rigorous, four-stage lifecycle designed specifically for non-deterministic AI systems.
          </p>
        </div>

        <div className="space-y-24">
          {steps.map((step, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className={`flex flex-col ${
                i % 2 === 0 ? 'md:flex-row' : 'md:flex-row-reverse'
              } gap-12 items-center`}
            >
              <div className="flex-1 space-y-6">
                <div className="w-16 h-16 rounded-2xl bg-blue-50 flex items-center justify-center text-blue-600 mb-4">
                  <step.icon size={32} />
                </div>
                <h2 className="text-3xl font-bold text-slate-900">{step.title}</h2>
                <p className="text-lg text-slate-500 leading-relaxed">{step.desc}</p>
                <ul className="space-y-3 pt-2">
                  {step.details.map((detail, idx) => (
                    <li key={idx} className="flex items-center gap-3 text-slate-700 font-medium">
                      <div className="w-6 h-6 rounded-full bg-green-100 flex items-center justify-center text-green-600">
                        <Check size={14} />
                      </div>
                      {detail}
                    </li>
                  ))}
                </ul>
              </div>
              <motion.div
                className="flex-1 w-full h-[320px] rounded-2xl border border-slate-200 overflow-hidden shadow-lg"
                whileHover={{ scale: 1.02 }}
                transition={{ type: 'spring', stiffness: 300, damping: 20 }}
              >
                <step.Visual />
              </motion.div>
            </motion.div>
          ))}
        </div>
      </main>
      <Footer />
    </>
  );
}
