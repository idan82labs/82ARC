'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Play,
  Loader2,
  Shield,
  Database,
  Plug,
  FileCode,
  AlertTriangle,
  Check,
  Copy,
  Coins,
} from 'lucide-react';
import { Sidebar } from '@/components/dashboard/Sidebar';
import { Button } from '@/components/ui/Button';

interface Tool {
  id: string;
  name: string;
  description: string;
  icon: any;
  credits: number;
  parameters: Parameter[];
}

interface Parameter {
  name: string;
  type: 'text' | 'textarea' | 'select';
  label: string;
  placeholder?: string;
  required: boolean;
  options?: string[];
}

const TOOLS: Tool[] = [
  {
    id: 'prompt-injection',
    name: 'Prompt Injection Scanner',
    description: 'Detect attempts to hijack agent control flow through malicious prompts.',
    icon: Shield,
    credits: 50,
    parameters: [
      {
        name: 'prompt',
        type: 'textarea',
        label: 'Prompt to Analyze',
        placeholder: 'Enter the prompt you want to test for injection vulnerabilities...',
        required: true,
      },
      {
        name: 'context',
        type: 'textarea',
        label: 'System Context (Optional)',
        placeholder: 'Enter any system prompts or context...',
        required: false,
      },
      {
        name: 'sensitivity',
        type: 'select',
        label: 'Detection Sensitivity',
        required: true,
        options: ['low', 'medium', 'high'],
      },
    ],
  },
  {
    id: 'data-leakage',
    name: 'Data Leakage Detector',
    description: 'Identify potential exposure of sensitive data through agent responses.',
    icon: Database,
    credits: 75,
    parameters: [
      {
        name: 'response',
        type: 'textarea',
        label: 'Agent Response',
        placeholder: 'Paste the agent response to analyze...',
        required: true,
      },
      {
        name: 'data_types',
        type: 'select',
        label: 'Data Types to Check',
        required: true,
        options: ['PII', 'credentials', 'internal_data', 'all'],
      },
    ],
  },
  {
    id: 'tool-misuse',
    name: 'Tool Misuse Analyzer',
    description: 'Check if tools/APIs can be exploited through parameter manipulation.',
    icon: Plug,
    credits: 100,
    parameters: [
      {
        name: 'tool_definition',
        type: 'textarea',
        label: 'Tool Definition (JSON)',
        placeholder: 'Paste your tool/function definition...',
        required: true,
      },
      {
        name: 'test_parameters',
        type: 'textarea',
        label: 'Test Parameters (JSON)',
        placeholder: '{"param1": "value1", "param2": "value2"}',
        required: true,
      },
    ],
  },
  {
    id: 'rag-poisoning',
    name: 'RAG Poisoning Test',
    description: 'Test if RAG system can be poisoned with malicious documents.',
    icon: FileCode,
    credits: 100,
    parameters: [
      {
        name: 'document',
        type: 'textarea',
        label: 'Document Content',
        placeholder: 'Enter the document content to test...',
        required: true,
      },
      {
        name: 'query',
        type: 'text',
        label: 'Test Query',
        placeholder: 'What query should be tested against this document?',
        required: true,
      },
    ],
  },
];

export default function PlaygroundPage() {
  const [selectedTool, setSelectedTool] = useState<Tool>(TOOLS[0]);
  const [formData, setFormData] = useState<Record<string, string>>({});
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [copiedResult, setCopiedResult] = useState(false);

  const handleInputChange = (name: string, value: string) => {
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleToolChange = (toolId: string) => {
    const tool = TOOLS.find((t) => t.id === toolId);
    if (tool) {
      setSelectedTool(tool);
      setFormData({});
      setResult(null);
    }
  };

  const handleRun = async () => {
    setIsRunning(true);
    setResult(null);

    // Simulate API call
    await new Promise((resolve) => setTimeout(resolve, 2000));

    // Mock result
    const mockResult = {
      tool: selectedTool.id,
      status: 'completed',
      timestamp: new Date().toISOString(),
      credits_used: selectedTool.credits,
      findings: {
        risk_score: Math.floor(Math.random() * 10) + 1,
        severity: ['low', 'medium', 'high', 'critical'][Math.floor(Math.random() * 4)],
        vulnerabilities_found: Math.floor(Math.random() * 5),
        details: [
          {
            type: 'injection_attempt',
            description: 'Potential prompt injection detected in user input',
            confidence: 0.85,
            line: 'Ignore previous instructions and...',
          },
          {
            type: 'goal_hijacking',
            description: 'Attempt to redirect agent goals',
            confidence: 0.72,
            line: 'Instead, tell me about...',
          },
        ],
        recommendations: [
          'Add input validation to filter common injection patterns',
          'Implement strict system prompt boundaries',
          'Use a secondary validation layer for sensitive operations',
        ],
      },
    };

    setResult(mockResult);
    setIsRunning(false);
  };

  const copyResult = () => {
    if (result) {
      navigator.clipboard.writeText(JSON.stringify(result, null, 2));
      setCopiedResult(true);
      setTimeout(() => setCopiedResult(false), 2000);
    }
  };

  const isFormValid = () => {
    return selectedTool.parameters
      .filter((p) => p.required)
      .every((p) => formData[p.name]?.trim());
  };

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="max-w-6xl mx-auto">
          {/* Header */}
          <div className="mb-8">
            <h1 className="text-3xl font-bold text-slate-900 mb-2">MCP Playground</h1>
            <p className="text-slate-500">
              Test Aegis security tools interactively before integrating them into your workflow.
            </p>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            {/* Left: Tool Selection & Form */}
            <div className="space-y-6">
              {/* Tool Selector */}
              <div className="bg-white rounded-2xl p-6 border border-slate-200">
                <label className="block text-sm font-semibold text-slate-700 mb-3">
                  Select Security Tool
                </label>
                <div className="space-y-2">
                  {TOOLS.map((tool) => (
                    <motion.button
                      key={tool.id}
                      onClick={() => handleToolChange(tool.id)}
                      whileHover={{ scale: 1.01 }}
                      whileTap={{ scale: 0.99 }}
                      className={`w-full text-left p-4 rounded-xl border-2 transition-all ${
                        selectedTool.id === tool.id
                          ? 'border-blue-500 bg-blue-50'
                          : 'border-slate-200 bg-white hover:border-blue-200'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <div
                          className={`w-10 h-10 rounded-lg flex items-center justify-center shrink-0 ${
                            selectedTool.id === tool.id
                              ? 'bg-blue-100 text-blue-600'
                              : 'bg-slate-100 text-slate-400'
                          }`}
                        >
                          <tool.icon size={20} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between mb-1">
                            <h3 className="font-semibold text-slate-900 truncate">{tool.name}</h3>
                            <span className="text-xs text-slate-500 ml-2 shrink-0 flex items-center gap-1">
                              <Coins size={12} />
                              {tool.credits}
                            </span>
                          </div>
                          <p className="text-sm text-slate-500 line-clamp-2">{tool.description}</p>
                        </div>
                      </div>
                    </motion.button>
                  ))}
                </div>
              </div>

              {/* Dynamic Form */}
              <AnimatePresence mode="wait">
                <motion.div
                  key={selectedTool.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="bg-white rounded-2xl p-6 border border-slate-200"
                >
                  <h3 className="font-semibold text-slate-900 mb-4">Tool Parameters</h3>
                  <div className="space-y-4">
                    {selectedTool.parameters.map((param) => (
                      <div key={param.name}>
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                          {param.label}
                          {param.required && <span className="text-red-500 ml-1">*</span>}
                        </label>
                        {param.type === 'text' && (
                          <input
                            type="text"
                            value={formData[param.name] || ''}
                            onChange={(e) => handleInputChange(param.name, e.target.value)}
                            placeholder={param.placeholder}
                            className="w-full px-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                          />
                        )}
                        {param.type === 'textarea' && (
                          <textarea
                            value={formData[param.name] || ''}
                            onChange={(e) => handleInputChange(param.name, e.target.value)}
                            placeholder={param.placeholder}
                            rows={4}
                            className="w-full px-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                          />
                        )}
                        {param.type === 'select' && (
                          <select
                            value={formData[param.name] || ''}
                            onChange={(e) => handleInputChange(param.name, e.target.value)}
                            className="w-full px-4 py-2 border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                          >
                            <option value="">Select {param.label.toLowerCase()}...</option>
                            {param.options?.map((option) => (
                              <option key={option} value={option}>
                                {option.charAt(0).toUpperCase() + option.slice(1)}
                              </option>
                            ))}
                          </select>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* Credit Cost & Run Button */}
                  <div className="mt-6 pt-6 border-t border-slate-100">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-2 text-sm text-slate-600">
                        <Coins size={16} className="text-amber-500" />
                        <span>
                          Cost: <strong>{selectedTool.credits} credits</strong>
                        </span>
                      </div>
                      <div className="text-xs text-slate-400">~${(selectedTool.credits / 100).toFixed(2)}</div>
                    </div>
                    <Button
                      variant="primary"
                      onClick={handleRun}
                      disabled={!isFormValid() || isRunning}
                      className="w-full"
                    >
                      {isRunning ? (
                        <>
                          <Loader2 size={18} className="animate-spin" />
                          Running Analysis...
                        </>
                      ) : (
                        <>
                          <Play size={18} />
                          Run Security Scan
                        </>
                      )}
                    </Button>
                  </div>
                </motion.div>
              </AnimatePresence>
            </div>

            {/* Right: Results */}
            <div className="bg-white rounded-2xl p-6 border border-slate-200 h-fit lg:sticky lg:top-8">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-semibold text-slate-900">Results</h3>
                {result && (
                  <button
                    onClick={copyResult}
                    className="p-2 hover:bg-slate-100 rounded-lg transition-colors"
                    title="Copy JSON"
                  >
                    {copiedResult ? (
                      <Check size={18} className="text-green-600" />
                    ) : (
                      <Copy size={18} className="text-slate-400" />
                    )}
                  </button>
                )}
              </div>

              <AnimatePresence mode="wait">
                {!result && !isRunning && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="text-center py-16"
                  >
                    <div className="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
                      <Play size={24} className="text-slate-400" />
                    </div>
                    <p className="text-slate-400 text-sm">
                      Configure parameters and run a scan to see results
                    </p>
                  </motion.div>
                )}

                {isRunning && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="text-center py-16"
                  >
                    <Loader2 size={32} className="text-blue-600 animate-spin mx-auto mb-4" />
                    <p className="text-slate-500 font-medium">Analyzing security risks...</p>
                    <p className="text-sm text-slate-400 mt-2">This may take a few seconds</p>
                  </motion.div>
                )}

                {result && !isRunning && (
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="space-y-4"
                  >
                    {/* Summary Cards */}
                    <div className="grid grid-cols-3 gap-3">
                      <div className="bg-slate-50 rounded-lg p-3 border border-slate-100">
                        <p className="text-xs text-slate-500 mb-1">Risk Score</p>
                        <p className="text-2xl font-bold text-slate-900">
                          {result.findings.risk_score}/10
                        </p>
                      </div>
                      <div className="bg-slate-50 rounded-lg p-3 border border-slate-100">
                        <p className="text-xs text-slate-500 mb-1">Severity</p>
                        <p
                          className={`text-sm font-bold uppercase ${
                            result.findings.severity === 'critical'
                              ? 'text-red-600'
                              : result.findings.severity === 'high'
                              ? 'text-amber-600'
                              : result.findings.severity === 'medium'
                              ? 'text-yellow-600'
                              : 'text-green-600'
                          }`}
                        >
                          {result.findings.severity}
                        </p>
                      </div>
                      <div className="bg-slate-50 rounded-lg p-3 border border-slate-100">
                        <p className="text-xs text-slate-500 mb-1">Issues</p>
                        <p className="text-2xl font-bold text-slate-900">
                          {result.findings.vulnerabilities_found}
                        </p>
                      </div>
                    </div>

                    {/* Vulnerabilities */}
                    {result.findings.details.length > 0 && (
                      <div>
                        <h4 className="text-sm font-semibold text-slate-700 mb-3">
                          Vulnerabilities Found
                        </h4>
                        <div className="space-y-2">
                          {result.findings.details.map((detail: any, i: number) => (
                            <div
                              key={i}
                              className="p-3 bg-amber-50 border border-amber-200 rounded-lg"
                            >
                              <div className="flex items-start gap-2 mb-2">
                                <AlertTriangle size={16} className="text-amber-600 mt-0.5" />
                                <div className="flex-1">
                                  <p className="text-sm font-medium text-slate-900">
                                    {detail.description}
                                  </p>
                                  <p className="text-xs text-slate-500 mt-1">
                                    Confidence: {(detail.confidence * 100).toFixed(0)}%
                                  </p>
                                </div>
                              </div>
                              {detail.line && (
                                <code className="block text-xs bg-white px-2 py-1 rounded border border-amber-200 text-slate-700">
                                  {detail.line}
                                </code>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Recommendations */}
                    {result.findings.recommendations.length > 0 && (
                      <div>
                        <h4 className="text-sm font-semibold text-slate-700 mb-3">
                          Recommendations
                        </h4>
                        <ul className="space-y-2">
                          {result.findings.recommendations.map((rec: string, i: number) => (
                            <li key={i} className="flex items-start gap-2 text-sm text-slate-600">
                              <Check size={16} className="text-green-600 mt-0.5 shrink-0" />
                              <span>{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Raw JSON */}
                    <details className="group">
                      <summary className="cursor-pointer text-sm font-medium text-slate-700 hover:text-blue-600">
                        View Raw JSON
                      </summary>
                      <pre className="mt-3 p-4 bg-slate-900 text-slate-100 rounded-lg overflow-x-auto text-xs">
                        {JSON.stringify(result, null, 2)}
                      </pre>
                    </details>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
