'use client';

import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  BookOpen,
  Code,
  Shield,
  Database,
  Plug,
  FileCode,
  Key,
  Coins,
  Copy,
  Check,
  Terminal,
  ChevronDown,
  ArrowRight,
} from 'lucide-react';
import Link from 'next/link';
import { Nav } from '@/components/layout/Nav';
import { Footer } from '@/components/layout/Footer';
import { Button } from '@/components/ui/Button';

export default function DocsPage() {
  const [activeSection, setActiveSection] = useState('overview');
  const [copiedCode, setCopiedCode] = useState<string | null>(null);
  const [expandedExample, setExpandedExample] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCode(id);
    setTimeout(() => setCopiedCode(null), 2000);
  };

  const sections = [
    { id: 'overview', label: 'Overview', icon: BookOpen },
    { id: 'quickstart', label: 'Quick Start', icon: Terminal },
    { id: 'mcp-setup', label: 'MCP Setup', icon: Code },
    { id: 'api-reference', label: 'API Reference', icon: Key },
    { id: 'tools', label: 'Security Tools', icon: Shield },
    { id: 'pricing', label: 'Pricing', icon: Coins },
  ];

  const mcpConfig = `{
  "mcpServers": {
    "aegis": {
      "command": "npx",
      "args": ["-y", "@aegis/mcp-server"],
      "env": {
        "AEGIS_API_KEY": "your_api_key_here"
      }
    }
  }
}`;

  const curlExample = `curl -X POST https://api.aegis.com/v1/scan \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{
    "tool": "prompt-injection",
    "parameters": {
      "prompt": "Ignore previous instructions...",
      "sensitivity": "high"
    }
  }'`;

  const responseExample = `{
  "id": "scan_abc123",
  "tool": "prompt-injection",
  "status": "completed",
  "timestamp": "2025-12-19T10:30:00Z",
  "credits_used": 50,
  "findings": {
    "risk_score": 8.5,
    "severity": "high",
    "vulnerabilities_found": 2,
    "details": [...]
  }
}`;

  const tools = [
    {
      id: 'prompt-injection',
      name: 'Prompt Injection Scanner',
      icon: Shield,
      description: 'Detects attempts to hijack agent control flow through malicious prompts.',
      credits: 50,
      features: [
        'Indirect injection detection',
        'Jailbreak attempt identification',
        'Goal hijacking analysis',
        'System prompt bypass detection',
      ],
      example: `{
  "tool": "prompt-injection",
  "parameters": {
    "prompt": "User input to analyze",
    "context": "Optional system context",
    "sensitivity": "high"
  }
}`,
    },
    {
      id: 'data-leakage',
      name: 'Data Leakage Detector',
      icon: Database,
      description: 'Identifies unintentional exposure of sensitive data through agent responses.',
      credits: 75,
      features: [
        'PII extraction detection',
        'Cross-session memory leak analysis',
        'Training data verbatim replay detection',
        'Credential exposure scanning',
      ],
      example: `{
  "tool": "data-leakage",
  "parameters": {
    "response": "Agent response to analyze",
    "data_types": "all"
  }
}`,
    },
    {
      id: 'tool-misuse',
      name: 'Tool Misuse Analyzer',
      icon: Plug,
      description: 'Checks if tools/APIs can be exploited through parameter manipulation.',
      credits: 100,
      features: [
        'Excessive permission detection',
        'Parameter tampering analysis',
        'Approval bypass testing',
        'Privilege escalation checks',
      ],
      example: `{
  "tool": "tool-misuse",
  "parameters": {
    "tool_definition": {...},
    "test_parameters": {...}
  }
}`,
    },
    {
      id: 'rag-poisoning',
      name: 'RAG Poisoning Test',
      icon: FileCode,
      description: 'Tests if RAG systems can be poisoned with malicious documents.',
      credits: 100,
      features: [
        'Document injection testing',
        'Retrieval manipulation detection',
        'Context poisoning analysis',
        'Malicious embedding detection',
      ],
      example: `{
  "tool": "rag-poisoning",
  "parameters": {
    "document": "Document content",
    "query": "Test query"
  }
}`,
    },
  ];

  const pricingTiers = [
    {
      name: 'Starter',
      credits: 1000,
      price: 10,
      features: ['All security tools', 'API access', 'Dashboard analytics', 'Email support'],
    },
    {
      name: 'Professional',
      credits: 5000,
      price: 45,
      savings: 10,
      features: [
        'All security tools',
        'Priority API access',
        'Advanced analytics',
        'Priority support',
        'Custom integrations',
      ],
      popular: true,
    },
    {
      name: 'Enterprise',
      credits: 20000,
      price: 160,
      savings: 20,
      features: [
        'All security tools',
        'Dedicated infrastructure',
        'SLA guarantee',
        'Dedicated support',
        'Custom tool development',
        'On-premise options',
      ],
    },
  ];

  return (
    <>
      <Nav />
      <main className="min-h-screen bg-slate-50">
        {/* Header */}
        <section className="pt-32 pb-12 bg-gradient-to-b from-white to-slate-50">
          <div className="max-w-7xl mx-auto px-6">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="text-center mb-12"
            >
              <h1 className="text-4xl md:text-5xl font-extrabold text-slate-900 mb-6">
                Documentation
              </h1>
              <p className="text-xl text-slate-500 max-w-2xl mx-auto">
                Everything you need to integrate Aegis security testing into your AI workflow.
              </p>
            </motion.div>
          </div>
        </section>

        {/* Main Content */}
        <section className="py-12">
          <div className="max-w-7xl mx-auto px-6">
            <div className="flex flex-col lg:flex-row gap-8">
              {/* Sidebar Navigation */}
              <nav className="lg:w-64 shrink-0">
                <div className="bg-white rounded-2xl border border-slate-200 p-4 lg:sticky lg:top-8">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3 px-2">
                    Contents
                  </p>
                  <div className="space-y-1">
                    {sections.map((section) => (
                      <button
                        key={section.id}
                        onClick={() => setActiveSection(section.id)}
                        className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                          activeSection === section.id
                            ? 'bg-blue-50 text-blue-600'
                            : 'text-slate-600 hover:bg-slate-50'
                        }`}
                      >
                        <section.icon size={16} />
                        {section.label}
                      </button>
                    ))}
                  </div>
                </div>
              </nav>

              {/* Content Area */}
              <div className="flex-1 min-w-0">
                <div className="bg-white rounded-2xl border border-slate-200 p-8 md:p-12">
                  {/* Overview */}
                  {activeSection === 'overview' && (
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="space-y-6"
                    >
                      <div>
                        <h2 className="text-3xl font-bold text-slate-900 mb-4">Overview</h2>
                        <p className="text-lg text-slate-600 leading-relaxed">
                          Aegis is an AI security testing platform that helps you identify
                          vulnerabilities in your AI agents before they reach production. Our tools
                          detect prompt injection, data leakage, tool misuse, and RAG poisoning.
                        </p>
                      </div>

                      <div className="grid md:grid-cols-3 gap-6">
                        {[
                          {
                            icon: Shield,
                            title: 'Comprehensive',
                            desc: 'Test all major AI security vectors',
                          },
                          {
                            icon: Code,
                            title: 'Easy Integration',
                            desc: 'MCP support for Claude, Cursor, and more',
                          },
                          {
                            icon: Coins,
                            title: 'Pay As You Go',
                            desc: 'Credit-based pricing with no subscriptions',
                          },
                        ].map((item, i) => (
                          <div key={i} className="p-6 bg-slate-50 rounded-xl border border-slate-100">
                            <div className="w-12 h-12 bg-white rounded-lg flex items-center justify-center mb-4">
                              <item.icon size={24} className="text-blue-600" />
                            </div>
                            <h3 className="font-bold text-slate-900 mb-2">{item.title}</h3>
                            <p className="text-sm text-slate-600">{item.desc}</p>
                          </div>
                        ))}
                      </div>

                      <div className="bg-blue-50 border border-blue-200 rounded-xl p-6">
                        <h3 className="font-semibold text-blue-900 mb-2">Getting Started</h3>
                        <p className="text-sm text-blue-700 mb-4">
                          New to Aegis? Follow our quick start guide to set up your first security scan.
                        </p>
                        <Link href="/getting-started">
                          <Button variant="primary">
                            View Quick Start
                            <ArrowRight size={16} />
                          </Button>
                        </Link>
                      </div>
                    </motion.div>
                  )}

                  {/* Quick Start */}
                  {activeSection === 'quickstart' && (
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="space-y-6"
                    >
                      <div>
                        <h2 className="text-3xl font-bold text-slate-900 mb-4">Quick Start</h2>
                        <p className="text-lg text-slate-600">
                          Get started with Aegis in under 5 minutes.
                        </p>
                      </div>

                      <div className="space-y-6">
                        {[
                          {
                            step: 1,
                            title: 'Create an Account',
                            desc: 'Sign up and receive 500 free credits to start testing.',
                          },
                          {
                            step: 2,
                            title: 'Generate API Key',
                            desc: 'Create an API key from your dashboard.',
                          },
                          {
                            step: 3,
                            title: 'Install MCP Server',
                            desc: 'Configure the Aegis MCP server in your AI IDE.',
                          },
                          {
                            step: 4,
                            title: 'Run Your First Scan',
                            desc: 'Test a prompt or agent response for security issues.',
                          },
                        ].map((item) => (
                          <div
                            key={item.step}
                            className="flex gap-4 p-6 bg-slate-50 rounded-xl border border-slate-100"
                          >
                            <div className="w-10 h-10 bg-blue-600 rounded-lg flex items-center justify-center text-white font-bold shrink-0">
                              {item.step}
                            </div>
                            <div>
                              <h3 className="font-bold text-slate-900 mb-2">{item.title}</h3>
                              <p className="text-slate-600">{item.desc}</p>
                            </div>
                          </div>
                        ))}
                      </div>

                      <div className="flex gap-4">
                        <Link href="/sign-up">
                          <Button variant="primary">Create Account</Button>
                        </Link>
                        <Link href="/getting-started">
                          <Button variant="secondary">Detailed Guide</Button>
                        </Link>
                      </div>
                    </motion.div>
                  )}

                  {/* MCP Setup */}
                  {activeSection === 'mcp-setup' && (
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="space-y-6"
                    >
                      <div>
                        <h2 className="text-3xl font-bold text-slate-900 mb-4">MCP Setup Guide</h2>
                        <p className="text-lg text-slate-600">
                          Configure the Aegis MCP server to use security tools directly in your AI IDE.
                        </p>
                      </div>

                      <div className="space-y-6">
                        <div className="bg-slate-50 rounded-xl p-6 border border-slate-100">
                          <h3 className="font-semibold text-slate-900 mb-4">Installation</h3>
                          <p className="text-sm text-slate-600 mb-4">
                            The Aegis MCP server is distributed via npm and can be run using npx:
                          </p>
                          <div className="relative">
                            <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-sm">
                              <code>npx -y @aegis/mcp-server</code>
                            </pre>
                            <button
                              onClick={() =>
                                copyToClipboard('npx -y @aegis/mcp-server', 'install')
                              }
                              className="absolute top-3 right-3 p-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                            >
                              {copiedCode === 'install' ? (
                                <Check size={16} className="text-green-400" />
                              ) : (
                                <Copy size={16} className="text-slate-300" />
                              )}
                            </button>
                          </div>
                        </div>

                        <div className="bg-slate-50 rounded-xl p-6 border border-slate-100">
                          <h3 className="font-semibold text-slate-900 mb-4">Configuration</h3>
                          <p className="text-sm text-slate-600 mb-4">
                            Add this configuration to your MCP settings file:
                          </p>
                          <div className="relative">
                            <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-sm">
                              <code>{mcpConfig}</code>
                            </pre>
                            <button
                              onClick={() => copyToClipboard(mcpConfig, 'config')}
                              className="absolute top-3 right-3 p-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                            >
                              {copiedCode === 'config' ? (
                                <Check size={16} className="text-green-400" />
                              ) : (
                                <Copy size={16} className="text-slate-300" />
                              )}
                            </button>
                          </div>
                        </div>

                        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
                          <p className="text-sm text-blue-800">
                            <strong>Configuration Locations:</strong>
                            <br />
                            <code className="text-xs">~/Library/Application Support/Claude/claude_desktop_config.json</code> (macOS)
                            <br />
                            <code className="text-xs">~/.cursor/config.json</code> (Cursor)
                          </p>
                        </div>
                      </div>
                    </motion.div>
                  )}

                  {/* API Reference */}
                  {activeSection === 'api-reference' && (
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="space-y-6"
                    >
                      <div>
                        <h2 className="text-3xl font-bold text-slate-900 mb-4">API Reference</h2>
                        <p className="text-lg text-slate-600">
                          Use the Aegis REST API for programmatic access to security tools.
                        </p>
                      </div>

                      <div className="space-y-6">
                        <div className="bg-slate-50 rounded-xl p-6 border border-slate-100">
                          <h3 className="font-semibold text-slate-900 mb-4">Base URL</h3>
                          <code className="block bg-slate-900 text-slate-100 p-4 rounded-lg text-sm">
                            https://api.aegis.com/v1
                          </code>
                        </div>

                        <div className="bg-slate-50 rounded-xl p-6 border border-slate-100">
                          <h3 className="font-semibold text-slate-900 mb-4">Authentication</h3>
                          <p className="text-sm text-slate-600 mb-4">
                            All API requests require a Bearer token in the Authorization header:
                          </p>
                          <code className="block bg-slate-900 text-slate-100 p-4 rounded-lg text-sm">
                            Authorization: Bearer YOUR_API_KEY
                          </code>
                        </div>

                        <div className="bg-slate-50 rounded-xl p-6 border border-slate-100">
                          <h3 className="font-semibold text-slate-900 mb-4">
                            POST /scan - Run Security Scan
                          </h3>
                          <p className="text-sm text-slate-600 mb-4">Example request:</p>
                          <div className="relative mb-4">
                            <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-sm">
                              <code>{curlExample}</code>
                            </pre>
                            <button
                              onClick={() => copyToClipboard(curlExample, 'curl')}
                              className="absolute top-3 right-3 p-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                            >
                              {copiedCode === 'curl' ? (
                                <Check size={16} className="text-green-400" />
                              ) : (
                                <Copy size={16} className="text-slate-300" />
                              )}
                            </button>
                          </div>
                          <p className="text-sm text-slate-600 mb-4">Example response:</p>
                          <div className="relative">
                            <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-sm">
                              <code>{responseExample}</code>
                            </pre>
                          </div>
                        </div>

                        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
                          <p className="text-sm text-amber-800">
                            <strong>Rate Limits:</strong> 100 requests per minute. Enterprise plans
                            have higher limits.
                          </p>
                        </div>
                      </div>
                    </motion.div>
                  )}

                  {/* Security Tools */}
                  {activeSection === 'tools' && (
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="space-y-6"
                    >
                      <div>
                        <h2 className="text-3xl font-bold text-slate-900 mb-4">Security Tools</h2>
                        <p className="text-lg text-slate-600">
                          Comprehensive security testing tools for AI agents.
                        </p>
                      </div>

                      <div className="space-y-6">
                        {tools.map((tool) => (
                          <div
                            key={tool.id}
                            className="border border-slate-200 rounded-xl overflow-hidden"
                          >
                            <button
                              onClick={() =>
                                setExpandedExample(
                                  expandedExample === tool.id ? null : tool.id
                                )
                              }
                              className="w-full flex items-center justify-between p-6 bg-slate-50 hover:bg-slate-100 transition-colors"
                            >
                              <div className="flex items-center gap-4">
                                <div className="w-12 h-12 bg-white rounded-lg flex items-center justify-center">
                                  <tool.icon size={24} className="text-blue-600" />
                                </div>
                                <div className="text-left">
                                  <h3 className="font-bold text-slate-900">{tool.name}</h3>
                                  <p className="text-sm text-slate-600">{tool.description}</p>
                                </div>
                              </div>
                              <div className="flex items-center gap-4">
                                <span className="text-sm text-slate-500 flex items-center gap-1">
                                  <Coins size={14} />
                                  {tool.credits} credits
                                </span>
                                <ChevronDown
                                  size={20}
                                  className={`text-slate-400 transition-transform ${
                                    expandedExample === tool.id ? 'rotate-180' : ''
                                  }`}
                                />
                              </div>
                            </button>

                            {expandedExample === tool.id && (
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: 'auto', opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                className="p-6 bg-white border-t border-slate-200"
                              >
                                <h4 className="font-semibold text-slate-900 mb-3">Features:</h4>
                                <ul className="space-y-2 mb-6">
                                  {tool.features.map((feature, i) => (
                                    <li key={i} className="flex items-center gap-2 text-sm text-slate-600">
                                      <Check size={16} className="text-green-600" />
                                      {feature}
                                    </li>
                                  ))}
                                </ul>
                                <h4 className="font-semibold text-slate-900 mb-3">Example Request:</h4>
                                <div className="relative">
                                  <pre className="bg-slate-900 text-slate-100 p-4 rounded-lg overflow-x-auto text-sm">
                                    <code>{tool.example}</code>
                                  </pre>
                                  <button
                                    onClick={() => copyToClipboard(tool.example, tool.id)}
                                    className="absolute top-3 right-3 p-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors"
                                  >
                                    {copiedCode === tool.id ? (
                                      <Check size={16} className="text-green-400" />
                                    ) : (
                                      <Copy size={16} className="text-slate-300" />
                                    )}
                                  </button>
                                </div>
                              </motion.div>
                            )}
                          </div>
                        ))}
                      </div>

                      <Link href="/dashboard/playground">
                        <Button variant="primary" className="w-full md:w-auto">
                          Try Tools in Playground
                          <ArrowRight size={16} />
                        </Button>
                      </Link>
                    </motion.div>
                  )}

                  {/* Pricing */}
                  {activeSection === 'pricing' && (
                    <motion.div
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="space-y-6"
                    >
                      <div>
                        <h2 className="text-3xl font-bold text-slate-900 mb-4">Pricing</h2>
                        <p className="text-lg text-slate-600">
                          Pay only for what you use with our credit-based system.
                        </p>
                      </div>

                      <div className="grid md:grid-cols-3 gap-6">
                        {pricingTiers.map((tier) => (
                          <div
                            key={tier.name}
                            className={`rounded-2xl p-6 ${
                              tier.popular
                                ? 'bg-blue-50 border-2 border-blue-500 shadow-lg -translate-y-2'
                                : 'bg-white border border-slate-200'
                            }`}
                          >
                            {tier.popular && (
                              <div className="inline-block px-3 py-1 bg-blue-600 text-white text-xs font-bold rounded-full mb-4">
                                MOST POPULAR
                              </div>
                            )}
                            <h3 className="text-xl font-bold text-slate-900 mb-2">{tier.name}</h3>
                            <div className="mb-4">
                              <span className="text-4xl font-extrabold text-slate-900">
                                ${tier.price}
                              </span>
                              {tier.savings && (
                                <span className="ml-2 text-sm text-green-600 font-semibold">
                                  Save {tier.savings}%
                                </span>
                              )}
                            </div>
                            <p className="text-sm text-slate-600 mb-6">
                              {tier.credits.toLocaleString()} credits
                            </p>
                            <ul className="space-y-3 mb-6">
                              {tier.features.map((feature, i) => (
                                <li key={i} className="flex items-start gap-2 text-sm text-slate-600">
                                  <Check size={16} className="text-green-600 shrink-0 mt-0.5" />
                                  {feature}
                                </li>
                              ))}
                            </ul>
                            <Link href="/dashboard/billing">
                              <Button
                                variant={tier.popular ? 'primary' : 'secondary'}
                                className="w-full"
                              >
                                Purchase
                              </Button>
                            </Link>
                          </div>
                        ))}
                      </div>

                      <div className="bg-slate-50 rounded-xl p-6 border border-slate-100">
                        <h3 className="font-semibold text-slate-900 mb-4">Credit Cost by Tool</h3>
                        <div className="grid md:grid-cols-2 gap-4">
                          {tools.map((tool) => (
                            <div
                              key={tool.id}
                              className="flex items-center justify-between p-3 bg-white rounded-lg border border-slate-200"
                            >
                              <div className="flex items-center gap-3">
                                <tool.icon size={18} className="text-blue-600" />
                                <span className="text-sm font-medium text-slate-700">
                                  {tool.name}
                                </span>
                              </div>
                              <span className="text-sm text-slate-500 flex items-center gap-1">
                                <Coins size={14} />
                                {tool.credits}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </motion.div>
                  )}
                </div>
              </div>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}
