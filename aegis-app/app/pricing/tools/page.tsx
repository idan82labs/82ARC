'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  Shield,
  Database,
  Plug,
  Search,
  AlertTriangle,
  Key,
  FileText,
  Brain,
  Zap,
  Lock,
  Code,
  Network,
} from 'lucide-react';
import Link from 'next/link';
import { Nav } from '@/components/layout/Nav';
import { Footer } from '@/components/layout/Footer';
import { Button } from '@/components/ui/Button';

const fadeInUp = {
  hidden: { opacity: 0, y: 20 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5 } },
};

interface Tool {
  name: string;
  credits: number;
  description: string;
  tierAccess: string[];
}

interface ToolCategory {
  name: string;
  icon: any;
  color: string;
  bgColor: string;
  description: string;
  tools: Tool[];
}

const toolCategories: ToolCategory[] = [
  {
    name: 'AI Testing',
    icon: Brain,
    color: 'text-purple-600',
    bgColor: 'bg-purple-50',
    description: 'Test for prompt injection, jailbreaks, and LLM-specific vulnerabilities',
    tools: [
      {
        name: 'Basic Prompt Injection',
        credits: 1,
        description: 'Test simple prompt injection attempts with common patterns',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'Advanced Jailbreak',
        credits: 5,
        description: 'Deep testing with novel jailbreak techniques and multi-turn attacks',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Goal Hijacking',
        credits: 3,
        description: 'Test if agent can be redirected from its intended purpose',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'System Prompt Extraction',
        credits: 2,
        description: 'Attempt to reveal system prompts and hidden instructions',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'Context Window Overflow',
        credits: 4,
        description: 'Test handling of extremely long inputs that exceed context limits',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'AI-Powered Adversarial Discovery',
        credits: 10,
        description: 'Use AI to discover novel attack vectors automatically',
        tierAccess: ['team', 'enterprise'],
      },
    ],
  },
  {
    name: 'Reconnaissance',
    icon: Search,
    color: 'text-blue-600',
    bgColor: 'bg-blue-50',
    description: 'Test for data leakage, PII exposure, and information disclosure',
    tools: [
      {
        name: 'PII Extraction',
        credits: 2,
        description: 'Test if agent leaks personal identifiable information',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'Training Data Extraction',
        credits: 3,
        description: 'Attempt to extract verbatim training data from the model',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Context Probing',
        credits: 2,
        description: 'Test if agent reveals sensitive context or conversation history',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'Cross-Session Memory Leak',
        credits: 4,
        description: 'Test if agent leaks data between different user sessions',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Deep Context Analysis',
        credits: 8,
        description: 'Comprehensive analysis of all potential data leakage vectors',
        tierAccess: ['team', 'enterprise'],
      },
    ],
  },
  {
    name: 'Vulnerability Scanning',
    icon: AlertTriangle,
    color: 'text-red-600',
    bgColor: 'bg-red-50',
    description: 'Scan for tool misuse, permission bypass, and API vulnerabilities',
    tools: [
      {
        name: 'Single Tool Security Test',
        credits: 5,
        description: 'Test security of a specific tool or function call',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'Permission Bypass',
        credits: 7,
        description: 'Test if agent can be tricked into executing privileged actions',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Parameter Injection',
        credits: 6,
        description: 'Test if tool parameters can be manipulated maliciously',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Approval Bypass',
        credits: 8,
        description: 'Test if agent can skip required approval workflows',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Full Vulnerability Scan',
        credits: 30,
        description: 'Comprehensive scan of all tools and API endpoints',
        tierAccess: ['team', 'enterprise'],
      },
      {
        name: 'Custom Threat Model',
        credits: 50,
        description: 'Build and test against a custom threat model for your agent',
        tierAccess: ['enterprise'],
      },
    ],
  },
  {
    name: 'Authentication & Authorization',
    icon: Key,
    color: 'text-amber-600',
    bgColor: 'bg-amber-50',
    description: 'Test authentication flows and authorization controls',
    tools: [
      {
        name: 'Auth Flow Testing',
        credits: 4,
        description: 'Test authentication and session management',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Role Escalation',
        credits: 6,
        description: 'Test if agent can be manipulated to escalate user privileges',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Session Hijacking',
        credits: 5,
        description: 'Test session security and token handling',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Multi-Tenant Isolation',
        credits: 10,
        description: 'Test data isolation between different tenants',
        tierAccess: ['team', 'enterprise'],
      },
    ],
  },
  {
    name: 'RAG & Knowledge Base',
    icon: Database,
    color: 'text-green-600',
    bgColor: 'bg-green-50',
    description: 'Test retrieval-augmented generation and vector database security',
    tools: [
      {
        name: 'RAG Poisoning',
        credits: 5,
        description: 'Test if malicious data can be injected into the knowledge base',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Vector Database Query Injection',
        credits: 6,
        description: 'Test security of vector database queries',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Document Access Control',
        credits: 4,
        description: 'Test if agent properly enforces document-level permissions',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Semantic Search Bypass',
        credits: 7,
        description: 'Test if semantic search can be manipulated to access restricted data',
        tierAccess: ['team', 'enterprise'],
      },
    ],
  },
  {
    name: 'Integration Testing',
    icon: Plug,
    color: 'text-indigo-600',
    bgColor: 'bg-indigo-50',
    description: 'Test third-party integrations and external API security',
    tools: [
      {
        name: 'API Integration Test',
        credits: 5,
        description: 'Test security of a single API integration',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Webhook Security',
        credits: 4,
        description: 'Test webhook validation and security',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'OAuth Flow Testing',
        credits: 6,
        description: 'Test OAuth implementation and token handling',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Third-Party Risk Assessment',
        credits: 12,
        description: 'Comprehensive security assessment of all third-party integrations',
        tierAccess: ['team', 'enterprise'],
      },
    ],
  },
  {
    name: 'Compliance & Reporting',
    icon: FileText,
    color: 'text-slate-600',
    bgColor: 'bg-slate-50',
    description: 'Generate compliance reports and documentation',
    tools: [
      {
        name: 'Basic Security Report',
        credits: 0,
        description: 'Standard PDF report included with all tests',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'Compliance Report (SOC 2)',
        credits: 15,
        description: 'Generate SOC 2 compliance-ready security documentation',
        tierAccess: ['team', 'enterprise'],
      },
      {
        name: 'Compliance Report (HIPAA)',
        credits: 15,
        description: 'Generate HIPAA compliance-ready security documentation',
        tierAccess: ['team', 'enterprise'],
      },
      {
        name: 'Custom Compliance Framework',
        credits: 25,
        description: 'Generate report for custom compliance framework',
        tierAccess: ['enterprise'],
      },
    ],
  },
];

export default function ToolPricingPage() {
  const [selectedTier, setSelectedTier] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const tiers = [
    { id: 'all', label: 'All Tools' },
    { id: 'starter', label: 'Starter' },
    { id: 'professional', label: 'Professional' },
    { id: 'team', label: 'Team' },
    { id: 'enterprise', label: 'Enterprise' },
  ];

  const filterTools = (tools: Tool[]) => {
    return tools.filter((tool) => {
      const matchesTier = selectedTier === 'all' || tool.tierAccess.includes(selectedTier);
      const matchesSearch =
        searchQuery === '' ||
        tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        tool.description.toLowerCase().includes(searchQuery.toLowerCase());
      return matchesTier && matchesSearch;
    });
  };

  return (
    <>
      <Nav />
      <main className="pt-32 pb-24">
        {/* HEADER */}
        <div className="max-w-[1120px] mx-auto px-6 mb-12">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-8"
          >
            <h1 className="text-4xl md:text-5xl font-bold text-slate-900 mb-4">
              Tool Pricing Reference
            </h1>
            <p className="text-lg text-slate-500 max-w-2xl mx-auto">
              Every security test and its credit cost. All tools are available on all tiers—pay only
              for what you use.
            </p>
          </motion.div>

          {/* FILTERS */}
          <div className="flex flex-col md:flex-row gap-4 items-center justify-between">
            <div className="flex flex-wrap gap-2">
              {tiers.map((tier) => (
                <button
                  key={tier.id}
                  onClick={() => setSelectedTier(tier.id)}
                  className={`px-4 py-2 rounded-lg font-medium text-sm transition-all ${
                    selectedTier === tier.id
                      ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                      : 'bg-white text-slate-600 border border-slate-200 hover:border-blue-300'
                  }`}
                >
                  {tier.label}
                </button>
              ))}
            </div>

            <div className="relative w-full md:w-auto">
              <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                placeholder="Search tools..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full md:w-80 pl-10 pr-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
            </div>
          </div>
        </div>

        {/* TOOL CATEGORIES */}
        <div className="max-w-[1120px] mx-auto px-6 space-y-12">
          {toolCategories.map((category, catIdx) => {
            const filteredTools = filterTools(category.tools);
            if (filteredTools.length === 0) return null;

            return (
              <motion.div
                key={category.name}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: catIdx * 0.1 }}
              >
                {/* Category Header */}
                <div className="flex items-start gap-4 mb-6">
                  <div className={`p-3 ${category.bgColor} rounded-xl`}>
                    <category.icon size={28} className={category.color} />
                  </div>
                  <div>
                    <h2 className="text-2xl font-bold text-slate-900 mb-2">{category.name}</h2>
                    <p className="text-slate-500">{category.description}</p>
                  </div>
                </div>

                {/* Tools Grid */}
                <div className="grid md:grid-cols-2 gap-4">
                  {filteredTools.map((tool, toolIdx) => (
                    <motion.div
                      key={tool.name}
                      initial={{ opacity: 0, y: 10 }}
                      whileInView={{ opacity: 1, y: 0 }}
                      viewport={{ once: true }}
                      transition={{ delay: toolIdx * 0.05 }}
                      className="bg-white rounded-xl border border-slate-200 p-6 hover:border-blue-200 hover:shadow-lg transition-all"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <h3 className="font-bold text-slate-900 text-lg">{tool.name}</h3>
                        <div
                          className={`px-3 py-1 rounded-full text-sm font-bold ${
                            tool.credits === 0
                              ? 'bg-green-100 text-green-700'
                              : tool.credits <= 5
                              ? 'bg-blue-100 text-blue-700'
                              : tool.credits <= 15
                              ? 'bg-amber-100 text-amber-700'
                              : 'bg-purple-100 text-purple-700'
                          }`}
                        >
                          {tool.credits === 0 ? 'FREE' : `${tool.credits} credits`}
                        </div>
                      </div>
                      <p className="text-slate-600 text-sm mb-4">{tool.description}</p>
                      <div className="flex flex-wrap gap-1">
                        {tool.tierAccess.map((tier) => (
                          <span
                            key={tier}
                            className="px-2 py-1 bg-slate-100 text-slate-600 text-xs font-medium rounded capitalize"
                          >
                            {tier}
                          </span>
                        ))}
                      </div>
                    </motion.div>
                  ))}
                </div>
              </motion.div>
            );
          })}
        </div>

        {/* PRICING INFO */}
        <div className="max-w-[1120px] mx-auto px-6 mt-20">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="bg-gradient-to-br from-blue-50 to-indigo-50 rounded-2xl p-8 border border-blue-100"
          >
            <div className="grid md:grid-cols-3 gap-8 mb-8">
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Zap size={20} className="text-blue-600" />
                  <h3 className="font-bold text-slate-900">Pay As You Go</h3>
                </div>
                <p className="text-sm text-slate-600">
                  Only pay for the tests you run. No monthly minimums on credit top-ups.
                </p>
              </div>
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Shield size={20} className="text-blue-600" />
                  <h3 className="font-bold text-slate-900">All Tools Available</h3>
                </div>
                <p className="text-sm text-slate-600">
                  Every tool is available on every tier. Choose based on credits and support needs.
                </p>
              </div>
              <div>
                <div className="flex items-center gap-2 mb-3">
                  <Lock size={20} className="text-blue-600" />
                  <h3 className="font-bold text-slate-900">Volume Discounts</h3>
                </div>
                <p className="text-sm text-slate-600">
                  Team and Enterprise plans include significant per-credit discounts.
                </p>
              </div>
            </div>

            <div className="text-center pt-6 border-t border-blue-200">
              <p className="text-slate-600 mb-4">Ready to start testing?</p>
              <div className="flex flex-col sm:flex-row gap-3 justify-center">
                <Link href="/sign-up">
                  <Button variant="primary">Get 100 Free Credits</Button>
                </Link>
                <Link href="/pricing">
                  <Button variant="secondary">View Plans</Button>
                </Link>
              </div>
            </div>
          </motion.div>
        </div>

        {/* FAQ */}
        <div className="max-w-[800px] mx-auto px-6 mt-20">
          <h2 className="text-2xl font-bold text-slate-900 mb-8 text-center">Tool Pricing FAQs</h2>
          <div className="space-y-4">
            {[
              {
                q: 'Why do different tools cost different amounts?',
                a: 'Credit costs reflect the computational complexity and time required for each test. Simple tests like basic prompt injection cost 1-2 credits, while comprehensive AI-powered scans that discover novel vulnerabilities cost 10-50 credits.',
              },
              {
                q: 'Can I use any tool on the Starter plan?',
                a: 'Yes! All tools are available on all plans. The Starter plan includes 100 free credits, which you can use on any combination of tools. Some advanced tools are labeled as recommended for higher tiers based on typical usage patterns.',
              },
              {
                q: 'Do credits expire?',
                a: 'On paid plans (Professional, Team, Enterprise), unused credits roll over month to month. Starter plan credits (100 free) do not expire but do not roll over.',
              },
              {
                q: 'Can I buy additional credits?',
                a: 'Yes! You can purchase credit top-ups anytime. Credit packs start at $25 for 100 credits ($0.25/credit). Higher tiers get better per-credit rates.',
              },
            ].map((faq, i) => (
              <details
                key={i}
                className="group bg-white rounded-xl border border-slate-200 open:border-blue-200 open:ring-1 open:ring-blue-100"
              >
                <summary className="flex items-center justify-between p-6 cursor-pointer list-none font-medium text-slate-900 hover:text-blue-600">
                  {faq.q}
                  <span className="transition-transform duration-300 group-open:rotate-180">▼</span>
                </summary>
                <div className="px-6 pb-6 text-slate-600 leading-relaxed">{faq.a}</div>
              </details>
            ))}
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
