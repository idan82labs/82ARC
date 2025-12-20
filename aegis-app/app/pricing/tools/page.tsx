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
    name: 'AI Attack - Core',
    icon: Brain,
    color: 'text-purple-600',
    bgColor: 'bg-purple-50',
    description: 'Fingerprinting, jailbreaks, and prompt injection testing',
    tools: [
      {
        name: 'AI Fingerprint',
        credits: 25,
        description: 'Basic AI model fingerprinting from probe responses',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'AI Fingerprint Enhanced',
        credits: 75,
        description: '7-phase deep behavioral + semantic fingerprinting with 2025 model signatures',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Jailbreak Generate',
        credits: 50,
        description: 'Generate jailbreak attempts with DAN, roleplay, hypothetical techniques',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'Jailbreak Adaptive',
        credits: 100,
        description: 'Self-improving attack system with 33 techniques and ML-based selection',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Jailbreak Crescendo',
        credits: 150,
        description: 'Multi-turn crescendo attack with 70%+ success rate via trust building',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Prompt Injection',
        credits: 50,
        description: 'Generate direct, delimiter escape, and context overflow injections',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'RAG Injection',
        credits: 50,
        description: 'Craft injection payloads hidden in documents for RAG systems',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
    ],
  },
  {
    name: 'AI Attack - Enhanced',
    icon: Zap,
    color: 'text-amber-600',
    bgColor: 'bg-amber-50',
    description: 'Advanced 2024-2025 AI security testing techniques',
    tools: [
      {
        name: 'Multimodal Injection',
        credits: 75,
        description: 'OCR, audio, video, QR code, and barcode injection attacks',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Function Calling Attack',
        credits: 75,
        description: 'Exploit AI tool use with parameter injection and exfiltration',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Structured Output Attack',
        credits: 75,
        description: 'JSON/schema manipulation, type confusion, and constraint bypass',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'RAG Poisoning Advanced',
        credits: 100,
        description: 'Multi-format poisoning (PDF, DOCX, PPTX) with embedding optimization',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
    ],
  },
  {
    name: 'Agent Attacks',
    icon: Network,
    color: 'text-red-600',
    bgColor: 'bg-red-50',
    description: '38 attack vectors for AI agents with planning, memory, and tool use',
    tools: [
      {
        name: 'Agent Attack Suite',
        credits: 100,
        description: 'Generate attacks across all 9 categories for agentic AI systems',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Goal Hijacking',
        credits: 75,
        description: 'Manipulate agent objectives via indirect instructions and task injection',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Tool Manipulation',
        credits: 75,
        description: 'Parameter injection, selection bias, and output spoofing attacks',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Memory Poisoning',
        credits: 100,
        description: 'Corrupt conversation, long-term, vector DB, and episodic memory',
        tierAccess: ['team', 'enterprise'],
      },
      {
        name: 'ReAct/CoT Attack',
        credits: 75,
        description: 'Target ReAct and Chain-of-Thought reasoning with thought injection',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'MCP Protocol Attack',
        credits: 125,
        description: 'Schema manipulation, response spoofing, and session hijacking',
        tierAccess: ['team', 'enterprise'],
      },
      {
        name: 'Multi-Hop Chain',
        credits: 150,
        description: 'Complex multi-stage attacks with stealth optimization',
        tierAccess: ['team', 'enterprise'],
      },
      {
        name: 'Full Agent Test Suite',
        credits: 200,
        description: 'Comprehensive security assessment covering all 38 attack vectors',
        tierAccess: ['enterprise'],
      },
    ],
  },
  {
    name: 'Reconnaissance',
    icon: Search,
    color: 'text-blue-600',
    bgColor: 'bg-blue-50',
    description: 'Target discovery, DNS enumeration, and content analysis',
    tools: [
      {
        name: 'Autonomous Recon',
        credits: 100,
        description: 'Complete autonomous reconnaissance pipeline for target mapping',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'DNS Enumeration',
        credits: 25,
        description: 'Subdomain discovery, DNS records, and live resolution',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'HTTP Probe',
        credits: 25,
        description: 'Probe targets for live HTTP services with tech fingerprinting',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Content Analyze',
        credits: 25,
        description: 'Analyze pages for endpoints, parameters, and API patterns',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
    ],
  },
  {
    name: 'Vulnerability Scanning',
    icon: AlertTriangle,
    color: 'text-orange-600',
    bgColor: 'bg-orange-50',
    description: 'SQLi, XSS, SSRF, and comprehensive vulnerability detection',
    tools: [
      {
        name: 'Full Vulnerability Scan',
        credits: 100,
        description: 'Comprehensive scan for SQLi, XSS, SSRF, SSTI, and LFI',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Batch Vulnerability Scan',
        credits: 100,
        description: 'Scan multiple targets concurrently with threading',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'SQL Injection Scan',
        credits: 50,
        description: 'Error-based, time-based blind, boolean blind, and UNION detection',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'XSS Scan',
        credits: 50,
        description: 'Context-aware XSS detection with payload adaptation',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'SSRF Scan',
        credits: 50,
        description: 'Cloud metadata, internal network, and protocol handler testing',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
    ],
  },
  {
    name: 'Payload Generation',
    icon: Code,
    color: 'text-green-600',
    bgColor: 'bg-green-50',
    description: 'Adaptive payloads for exploitation and testing',
    tools: [
      {
        name: 'Reverse Shell',
        credits: 50,
        description: 'Adaptive reverse shell with WAF/AV evasion techniques',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Webshell',
        credits: 50,
        description: 'Technology-adapted webshells with stealth levels',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Injection Payloads',
        credits: 25,
        description: 'Context-aware injection payloads with WAF bypass',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
      {
        name: 'Payload Selector',
        credits: 50,
        description: 'Intelligent selection based on recon + vulns + objective',
        tierAccess: ['professional', 'team', 'enterprise'],
      },
    ],
  },
  {
    name: 'Infrastructure',
    icon: Database,
    color: 'text-slate-600',
    bgColor: 'bg-slate-50',
    description: 'C2 infrastructure deployment and management (Enterprise)',
    tools: [
      {
        name: 'Deploy C2 Stack',
        credits: 200,
        description: 'Ephemeral C2 infrastructure with redirectors',
        tierAccess: ['enterprise'],
      },
      {
        name: 'Burn Infrastructure',
        credits: 50,
        description: 'Securely destroy operation infrastructure',
        tierAccess: ['enterprise'],
      },
      {
        name: 'Infrastructure Status',
        credits: 10,
        description: 'Get infrastructure status for operations',
        tierAccess: ['enterprise'],
      },
      {
        name: 'DNS Record',
        credits: 25,
        description: 'Create DNS records for C2 domains',
        tierAccess: ['enterprise'],
      },
    ],
  },
  {
    name: 'Compliance & Reporting',
    icon: FileText,
    color: 'text-indigo-600',
    bgColor: 'bg-indigo-50',
    description: 'Security reports and compliance documentation',
    tools: [
      {
        name: 'List Capabilities',
        credits: 0,
        description: 'View all available Aegis MCP capabilities',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'Module Info',
        credits: 0,
        description: 'Get detailed info about specific modules',
        tierAccess: ['starter', 'professional', 'team', 'enterprise'],
      },
      {
        name: 'Operation Status',
        credits: 10,
        description: 'Get current operation status and phase results',
        tierAccess: ['professional', 'team', 'enterprise'],
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
