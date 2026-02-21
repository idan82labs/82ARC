'use client';

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  Activity,
  Database,
  Globe,
  Lock,
  AlertTriangle,
  Shield,
  Check,
} from 'lucide-react';

export const ScanVisual: React.FC = () => {
  return (
    <div className="relative w-full h-full bg-slate-900 overflow-hidden flex items-center justify-center group">
      {/* Grid */}
      <div
        className="absolute inset-0 opacity-20"
        style={{
          backgroundImage:
            'linear-gradient(#3b82f6 1px, transparent 1px), linear-gradient(90deg, #3b82f6 1px, transparent 1px)',
          backgroundSize: '30px 30px',
        }}
      ></div>

      {/* Radar Circle */}
      <div className="relative w-48 h-48 rounded-full border border-blue-500/30 flex items-center justify-center">
        <div className="absolute w-32 h-32 rounded-full border border-blue-500/50"></div>
        <div className="absolute w-16 h-16 rounded-full border border-blue-500/70 bg-blue-500/10"></div>

        {/* Scanning Line */}
        <motion.div
          animate={{ rotate: 360 }}
          transition={{ duration: 3, repeat: Infinity, ease: 'linear' }}
          className="absolute w-full h-full rounded-full origin-center"
          style={{
            background:
              'conic-gradient(from 0deg, transparent 0deg, transparent 270deg, rgba(59, 130, 246, 0.4) 360deg)',
          }}
        />

        {/* Asset Dots */}
        {[0, 1, 2].map((i) => (
          <motion.div
            key={i}
            className="absolute w-3 h-3 bg-blue-400 rounded-full shadow-[0_0_10px_#60a5fa]"
            style={{
              top: 20 + i * 30,
              left: 20 + i * 20,
            }}
            animate={{ opacity: [0, 1, 0], scale: [0, 1.2, 0] }}
            transition={{ duration: 2, repeat: Infinity, delay: i * 0.8 }}
          >
            <div className="absolute top-4 left-4 text-[10px] text-blue-300 font-mono whitespace-nowrap bg-slate-900/80 px-1 rounded">
              {['API_KEY', 'SQL_DB', 'PII_VEC'][i]}
            </div>
          </motion.div>
        ))}
      </div>

      <div className="absolute bottom-4 left-4 text-blue-400 font-mono text-xs flex items-center gap-2">
        <Activity size={14} className="animate-pulse" /> Mapping Attack Surface...
      </div>
    </div>
  );
};

export const ThreatVisual: React.FC = () => {
  return (
    <div className="relative w-full h-full bg-slate-50 overflow-hidden flex flex-col items-center justify-center p-8 group">
      {/* Nodes */}
      <div className="flex justify-between w-full max-w-[200px] mb-8 relative z-10">
        <motion.div
          whileHover={{ scale: 1.1 }}
          className="w-12 h-12 bg-white border-2 border-slate-300 rounded-lg flex items-center justify-center shadow-sm"
        >
          <Database size={20} className="text-slate-400" />
        </motion.div>
        <motion.div
          whileHover={{ scale: 1.1 }}
          className="w-12 h-12 bg-white border-2 border-slate-300 rounded-lg flex items-center justify-center shadow-sm"
        >
          <Globe size={20} className="text-slate-400" />
        </motion.div>
      </div>

      <div className="w-0.5 h-12 bg-slate-300 mb-8 relative">
        <motion.div
          animate={{ y: [0, 48, 0] }}
          transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
          className="absolute top-0 left-1/2 -translate-x-1/2 w-2 h-2 bg-slate-400 rounded-full"
        />
      </div>

      <motion.div
        className="w-16 h-16 bg-white border-2 border-red-200 rounded-xl flex items-center justify-center shadow-lg relative"
        animate={{ borderColor: ['#e2e8f0', '#fecaca', '#e2e8f0'] }}
        transition={{ duration: 3, repeat: Infinity }}
      >
        <Lock size={24} className="text-slate-400" />
        <motion.div
          className="absolute -top-1 -right-1 w-4 h-4 bg-red-500 rounded-full flex items-center justify-center"
          animate={{ scale: [0, 1.2, 1] }}
          transition={{ duration: 0.5, delay: 1, repeat: Infinity, repeatDelay: 2.5 }}
        >
          <AlertTriangle size={10} className="text-white" />
        </motion.div>
      </motion.div>

      {/* Connecting lines SVG */}
      <svg className="absolute inset-0 w-full h-full pointer-events-none z-0 opacity-20">
        <path d="M120 100 Q 160 150 200 100" fill="none" stroke="black" strokeDasharray="4 4" />
      </svg>

      <div className="absolute bottom-4 w-full text-center text-slate-400 text-xs font-mono">
        Scenario: Privilege Escalation
      </div>
    </div>
  );
};

export const AttackVisual: React.FC = () => {
  const [lines, setLines] = useState<string[]>([]);

  useEffect(() => {
    const sequence = [
      '> init_probe --target=agent_v2',
      '> injecting prompt payload...',
      '> bypass detected: 200 OK',
      '> dumping context window...',
      '> connection closed.',
    ];
    let i = 0;
    const interval = setInterval(() => {
      setLines((prev) => {
        const newLines = [...prev, sequence[i % sequence.length]];
        if (newLines.length > 6) newLines.shift();
        return newLines;
      });
      i++;
    }, 800);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative w-full h-full bg-slate-950 font-mono text-xs p-6 flex flex-col justify-end overflow-hidden">
      <div className="absolute top-0 left-0 right-0 h-6 bg-slate-800 flex items-center px-2 gap-1.5">
        <div className="w-2.5 h-2.5 rounded-full bg-red-500"></div>
        <div className="w-2.5 h-2.5 rounded-full bg-amber-500"></div>
        <div className="w-2.5 h-2.5 rounded-full bg-green-500"></div>
      </div>
      <div className="space-y-2 relative z-10 pt-8">
        {lines.map((line, idx) => (
          <motion.div
            key={idx}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            className={`${
              line.includes('bypass')
                ? 'text-green-400'
                : line.includes('injecting')
                ? 'text-amber-400'
                : 'text-slate-300'
            }`}
          >
            {line}
          </motion.div>
        ))}
        <motion.div
          animate={{ opacity: [0, 1] }}
          transition={{ repeat: Infinity, duration: 0.8 }}
          className="w-2 h-4 bg-slate-400 inline-block align-middle"
        />
      </div>
    </div>
  );
};

export const ReportVisual: React.FC = () => {
  return (
    <div className="relative w-full h-full bg-slate-100 flex items-center justify-center p-8">
      <div className="w-48 bg-white rounded-lg shadow-xl border border-slate-200 p-4 relative overflow-hidden">
        {/* Document Header */}
        <div className="flex gap-2 mb-4">
          <div className="w-8 h-8 bg-blue-100 rounded flex items-center justify-center text-blue-600">
            <Shield size={16} />
          </div>
          <div className="flex-1 space-y-1">
            <div className="h-2 bg-slate-200 rounded w-full"></div>
            <div className="h-2 bg-slate-200 rounded w-1/2"></div>
          </div>
        </div>

        {/* Checkbox List */}
        <div className="space-y-2 mb-4">
          {[0, 1, 2].map((i) => (
            <motion.div
              key={i}
              className="flex items-center gap-2"
              initial={{ opacity: 0.5 }}
              animate={{ opacity: 1 }}
              transition={{ delay: i * 0.5, repeat: Infinity, repeatDelay: 3 }}
            >
              <motion.div
                className="w-4 h-4 rounded-full bg-green-100 flex items-center justify-center text-green-600"
                animate={{ scale: [1, 1.2, 1] }}
                transition={{ delay: i * 0.5, repeat: Infinity, repeatDelay: 3 }}
              >
                <Check size={10} />
              </motion.div>
              <div className="h-1.5 bg-slate-100 rounded w-20"></div>
            </motion.div>
          ))}
        </div>

        {/* Animated Stamp */}
        <motion.div
          className="absolute bottom-2 right-2 border-2 border-green-500 text-green-600 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider -rotate-12 bg-green-50/90 backdrop-blur-sm"
          initial={{ scale: 2, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ delay: 2, repeat: Infinity, repeatDelay: 3, duration: 0.3 }}
        >
          Passed
        </motion.div>
      </div>
    </div>
  );
};
