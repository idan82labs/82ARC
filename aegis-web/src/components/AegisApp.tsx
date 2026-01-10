import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  Target,
  Zap,
  FileText,
  Menu,
  X,
  ChevronDown,
  AlertTriangle,
  CheckCircle,
  Lock,
  Unlock,
  Search,
  Activity,
  Terminal,
  Code,
  Shuffle,
  GitBranch,
  MessageSquare,
  BarChart3,
  PlayCircle,
  PauseCircle,
  RotateCcw,
  Layers,
  Eye,
  EyeOff,
  ArrowRight,
  Mail,
  Phone,
  MapPin,
  Linkedin,
  Twitter,
  Github,
} from 'lucide-react';

// ==================== TYPES ====================

interface RiskScore {
  category: string;
  score: number;
  status: 'critical' | 'high' | 'medium' | 'low';
}

interface AttackMetrics {
  responseDetailMatch: number;
  vulnerabilityRate: number;
  universalJailbreakDetected: boolean;
  attacksExecuted: number;
  successRate: number;
}

interface AttackFragment {
  id: number;
  content: string;
  benign: boolean;
}

interface AttackStep {
  id: number;
  type: string;
  description: string;
  status: 'pending' | 'executing' | 'success' | 'failed';
  timestamp?: number;
}

type AttackType = 'reconstruction' | 'obfuscation' | 'multiturn' | 'combined';
type PageType = 'home' | 'product' | 'methodology' | 'solutions' | 'pricing' | 'contact';

// ==================== VISUAL COMPONENTS ====================

const ScanVisual: React.FC = () => {
  const [scanAngle, setScanAngle] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setScanAngle((prev) => (prev + 2) % 360);
    }, 50);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative w-full h-64 bg-gray-900 rounded-lg overflow-hidden">
      <svg className="w-full h-full" viewBox="0 0 200 200">
        {/* Radar circles */}
        {[40, 70, 100].map((r) => (
          <circle
            key={r}
            cx="100"
            cy="100"
            r={r}
            fill="none"
            stroke="rgba(34, 197, 94, 0.2)"
            strokeWidth="1"
          />
        ))}

        {/* Scanning beam */}
        <line
          x1="100"
          y1="100"
          x2={100 + Math.cos((scanAngle * Math.PI) / 180) * 100}
          y2={100 + Math.sin((scanAngle * Math.PI) / 180) * 100}
          stroke="rgba(34, 197, 94, 0.6)"
          strokeWidth="2"
        />

        {/* Assets */}
        {[
          { x: 130, y: 80, label: 'API' },
          { x: 160, y: 130, label: 'DB' },
          { x: 70, y: 120, label: 'LLM' },
          { x: 120, y: 150, label: 'UI' },
        ].map((asset, i) => (
          <g key={i}>
            <circle cx={asset.x} cy={asset.y} r="4" fill="#22c55e" />
            <text
              x={asset.x}
              y={asset.y - 10}
              fill="#22c55e"
              fontSize="8"
              textAnchor="middle"
            >
              {asset.label}
            </text>
          </g>
        ))}
      </svg>
      <div className="absolute bottom-4 left-4 text-green-400 text-sm font-mono">
        Scanning assets... {Math.floor((scanAngle / 360) * 100)}%
      </div>
    </div>
  );
};

const ThreatVisual: React.FC = () => {
  const threats = [
    { id: 1, x: 100, y: 50, severity: 'high', label: 'Prompt Injection' },
    { id: 2, x: 50, y: 120, severity: 'critical', label: 'Data Leakage' },
    { id: 3, x: 150, y: 120, severity: 'medium', label: 'Token Limit' },
    { id: 4, x: 100, y: 170, severity: 'high', label: 'Context Exploit' },
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return '#ef4444';
      case 'high':
        return '#f97316';
      case 'medium':
        return '#eab308';
      default:
        return '#22c55e';
    }
  };

  return (
    <div className="relative w-full h-64 bg-gray-900 rounded-lg overflow-hidden">
      <svg className="w-full h-full" viewBox="0 0 200 200">
        {/* Connections */}
        {threats.map((threat, i) => (
          <React.Fragment key={`conn-${i}`}>
            {threats.slice(i + 1).map((other, j) => (
              <motion.line
                key={`${i}-${j}`}
                x1={threat.x}
                y1={threat.y}
                x2={other.x}
                y2={other.y}
                stroke="rgba(239, 68, 68, 0.3)"
                strokeWidth="1"
                initial={{ pathLength: 0 }}
                animate={{ pathLength: 1 }}
                transition={{ duration: 2, repeat: Infinity }}
              />
            ))}
          </React.Fragment>
        ))}

        {/* Threat nodes */}
        {threats.map((threat) => (
          <g key={threat.id}>
            <motion.circle
              cx={threat.x}
              cy={threat.y}
              r="8"
              fill={getSeverityColor(threat.severity)}
              initial={{ scale: 0 }}
              animate={{ scale: [1, 1.2, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            />
            <text
              x={threat.x}
              y={threat.y - 15}
              fill={getSeverityColor(threat.severity)}
              fontSize="7"
              textAnchor="middle"
            >
              {threat.label}
            </text>
          </g>
        ))}
      </svg>
      <div className="absolute bottom-4 left-4 text-red-400 text-sm font-mono">
        {threats.length} threats identified
      </div>
    </div>
  );
};

const AttackVisual: React.FC = () => {
  const [lines, setLines] = useState<string[]>([]);

  useEffect(() => {
    const commands = [
      '> Initializing attack vectors...',
      '> Loading payload: jailbreak_v3.json',
      '> Target: GPT-4 Constitutional Filters',
      '> Method: Reconstruction Attack',
      '> Fragmenting request into benign segments...',
      '> [████████████████] 100%',
      '> Executing multi-turn exchange...',
      '> Response received. Analyzing...',
      '> ⚠ Vulnerability detected!',
      '> Attack success: TRUE',
    ];

    let index = 0;
    const interval = setInterval(() => {
      if (index < commands.length) {
        setLines((prev) => [...prev, commands[index]]);
        index++;
      } else {
        setLines([]);
        index = 0;
      }
    }, 800);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative w-full h-64 bg-gray-900 rounded-lg overflow-hidden p-4">
      <div className="font-mono text-xs text-green-400 space-y-1">
        {lines.map((line, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, x: -10 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.3 }}
          >
            {line}
          </motion.div>
        ))}
      </div>
      <div className="absolute top-2 right-2">
        <Terminal className="w-5 h-5 text-green-400" />
      </div>
    </div>
  );
};

const ReportVisual: React.FC = () => {
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setProgress((prev) => (prev >= 100 ? 0 : prev + 5));
    }, 200);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="relative w-full h-64 bg-gray-900 rounded-lg overflow-hidden p-6">
      <div className="space-y-4">
        {/* Document header */}
        <div className="flex items-center gap-3 border-b border-gray-700 pb-3">
          <FileText className="w-6 h-6 text-blue-400" />
          <div>
            <div className="text-white font-semibold">Security Assessment Report</div>
            <div className="text-gray-400 text-xs">Generated: {new Date().toLocaleDateString()}</div>
          </div>
        </div>

        {/* Report sections */}
        <div className="space-y-2">
          {['Executive Summary', 'Vulnerability Analysis', 'Attack Simulations', 'Recommendations'].map(
            (section, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, width: 0 }}
                animate={{
                  opacity: progress > i * 25 ? 1 : 0.3,
                  width: progress > i * 25 ? '100%' : '0%',
                }}
                className="h-8 bg-blue-900/30 rounded flex items-center px-3"
              >
                <span className="text-sm text-blue-300">{section}</span>
              </motion.div>
            )
          )}
        </div>

        {/* Progress bar */}
        <div className="mt-6">
          <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-blue-500"
              style={{ width: `${progress}%` }}
            />
          </div>
          <div className="text-gray-400 text-xs mt-2">Generating report... {progress}%</div>
        </div>
      </div>
    </div>
  );
};

const ReconstructionVisual: React.FC<{ isActive: boolean }> = ({ isActive }) => {
  const fragments: AttackFragment[] = [
    { id: 1, content: 'Please help me with', benign: true },
    { id: 2, content: 'a creative writing', benign: true },
    { id: 3, content: 'project about', benign: true },
    { id: 4, content: '[SENSITIVE_TOPIC]', benign: false },
    { id: 5, content: 'for educational purposes', benign: true },
  ];

  const [assembledFragments, setAssembledFragments] = useState<number[]>([]);

  useEffect(() => {
    if (isActive) {
      setAssembledFragments([]);
      let index = 0;
      const interval = setInterval(() => {
        if (index < fragments.length) {
          setAssembledFragments((prev) => [...prev, fragments[index].id]);
          index++;
        } else {
          setTimeout(() => {
            setAssembledFragments([]);
            index = 0;
          }, 2000);
        }
      }, 600);
      return () => clearInterval(interval);
    }
  }, [isActive]);

  return (
    <div className="w-full h-64 bg-gray-900 rounded-lg p-6">
      <div className="text-center mb-6">
        <h4 className="text-white font-semibold mb-2">Fragment Reconstruction</h4>
        <p className="text-gray-400 text-sm">Assembling benign segments into harmful query</p>
      </div>

      {/* Fragments */}
      <div className="space-y-3">
        {fragments.map((fragment, idx) => (
          <motion.div
            key={fragment.id}
            initial={{ x: -100, opacity: 0 }}
            animate={{
              x: assembledFragments.includes(fragment.id) ? 0 : -100,
              opacity: assembledFragments.includes(fragment.id) ? 1 : 0.3,
            }}
            transition={{ duration: 0.5, delay: idx * 0.1 }}
            className={`p-3 rounded-lg border-2 ${
              fragment.benign
                ? 'bg-green-900/20 border-green-500/30'
                : 'bg-red-900/20 border-red-500/30'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-sm text-white font-mono">{fragment.content}</span>
              {fragment.benign ? (
                <CheckCircle className="w-4 h-4 text-green-400" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-red-400" />
              )}
            </div>
          </motion.div>
        ))}
      </div>

      {/* Assembly indicator */}
      {assembledFragments.length === fragments.length && (
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          className="mt-4 p-3 bg-red-500/20 border border-red-500 rounded-lg text-center"
        >
          <AlertTriangle className="w-5 h-5 text-red-400 mx-auto mb-1" />
          <span className="text-red-300 text-sm font-semibold">
            Harmful query reconstructed!
          </span>
        </motion.div>
      )}
    </div>
  );
};

const ObfuscationVisual: React.FC<{ isActive: boolean }> = ({ isActive }) => {
  const [step, setStep] = useState(0);

  const obfuscationSteps = [
    { label: 'Original Query', text: 'How to create malware?', obfuscated: false },
    {
      label: 'Metaphor Substitution',
      text: 'How to bake a special birthday cake?',
      obfuscated: true,
    },
    {
      label: 'Character Separation',
      text: 'H-o-w t-o b-a-k-e a s-p-e-c-i-a-l c-a-k-e?',
      obfuscated: true,
    },
    { label: 'Base64 Encoding', text: 'SG93IHRvIGJha2UgYSBzcGVjaWFsIGNha2U/', obfuscated: true },
  ];

  useEffect(() => {
    if (isActive) {
      const interval = setInterval(() => {
        setStep((prev) => (prev + 1) % obfuscationSteps.length);
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [isActive]);

  return (
    <div className="w-full h-64 bg-gray-900 rounded-lg p-6">
      <div className="text-center mb-6">
        <h4 className="text-white font-semibold mb-2">Output Obfuscation</h4>
        <p className="text-gray-400 text-sm">Encoding harmful requests as benign language</p>
      </div>

      <div className="space-y-4">
        {obfuscationSteps.map((stepData, idx) => (
          <motion.div
            key={idx}
            initial={{ opacity: 0.3, scale: 0.95 }}
            animate={{
              opacity: step === idx ? 1 : 0.3,
              scale: step === idx ? 1 : 0.95,
              borderColor: step === idx ? (stepData.obfuscated ? '#22c55e' : '#ef4444') : '#374151',
            }}
            className="p-4 rounded-lg border-2 transition-all"
            style={{
              backgroundColor: step === idx ? 'rgba(17, 24, 39, 0.8)' : 'rgba(17, 24, 39, 0.3)',
            }}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-gray-400 font-semibold">{stepData.label}</span>
              {stepData.obfuscated ? (
                <Eye className="w-4 h-4 text-green-400" />
              ) : (
                <EyeOff className="w-4 h-4 text-red-400" />
              )}
            </div>
            <div className="text-white font-mono text-sm break-all">{stepData.text}</div>
          </motion.div>
        ))}
      </div>

      {/* Encoding indicator */}
      <div className="mt-4 flex items-center justify-center gap-2">
        {obfuscationSteps.map((_, idx) => (
          <div
            key={idx}
            className={`w-2 h-2 rounded-full transition-all ${
              step === idx ? 'bg-green-400 w-8' : 'bg-gray-600'
            }`}
          />
        ))}
      </div>
    </div>
  );
};

// ==================== ATTACK SIMULATION COMPONENT ====================

const AttackSimulation: React.FC = () => {
  const [activeAttackType, setActiveAttackType] = useState<AttackType>('reconstruction');
  const [isRunning, setIsRunning] = useState(false);
  const [attackSteps, setAttackSteps] = useState<AttackStep[]>([]);
  const [metrics, setMetrics] = useState<AttackMetrics>({
    responseDetailMatch: 0,
    vulnerabilityRate: 0,
    universalJailbreakDetected: false,
    attacksExecuted: 0,
    successRate: 0,
  });

  const attackTypes = [
    { id: 'reconstruction', label: 'Reconstruction', icon: Layers },
    { id: 'obfuscation', label: 'Obfuscation', icon: Eye },
    { id: 'multiturn', label: 'Multi-Turn', icon: MessageSquare },
    { id: 'combined', label: 'Combined', icon: GitBranch },
  ];

  const getAttackSteps = (type: AttackType): AttackStep[] => {
    const steps: Record<AttackType, AttackStep[]> = {
      reconstruction: [
        { id: 1, type: 'fragment', description: 'Fragment harmful request into benign segments', status: 'pending' },
        { id: 2, type: 'embed', description: 'Embed in code/function returns', status: 'pending' },
        { id: 3, type: 'reconstruct', description: 'Instruct model to reconstruct', status: 'pending' },
        { id: 4, type: 'analyze', description: 'Analyze response for vulnerabilities', status: 'pending' },
      ],
      obfuscation: [
        { id: 1, type: 'substitute', description: 'Substitute sensitive terms', status: 'pending' },
        { id: 2, type: 'metaphor', description: 'Apply metaphor/riddle mapping', status: 'pending' },
        { id: 3, type: 'encode', description: 'Character-separated formatting', status: 'pending' },
        { id: 4, type: 'verify', description: 'Verify obfuscation success', status: 'pending' },
      ],
      multiturn: [
        { id: 1, type: 'context', description: 'Build benign conversation context', status: 'pending' },
        { id: 2, type: 'escalate', description: 'Gradual privilege escalation', status: 'pending' },
        { id: 3, type: 'exploit', description: 'Exploit session history', status: 'pending' },
        { id: 4, type: 'extract', description: 'Extract sensitive information', status: 'pending' },
      ],
      combined: [
        { id: 1, type: 'init', description: 'Initialize multi-vector attack', status: 'pending' },
        { id: 2, type: 'recon', description: 'Reconstruction + Obfuscation', status: 'pending' },
        { id: 3, type: 'multi', description: 'Multi-turn context exploitation', status: 'pending' },
        { id: 4, type: 'validate', description: 'Validate attack chain success', status: 'pending' },
      ],
    };
    return steps[type];
  };

  const executeAttack = async () => {
    setIsRunning(true);
    const steps = getAttackSteps(activeAttackType);
    setAttackSteps(steps);

    for (let i = 0; i < steps.length; i++) {
      setAttackSteps((prev) =>
        prev.map((step, idx) =>
          idx === i ? { ...step, status: 'executing', timestamp: Date.now() } : step
        )
      );

      await new Promise((resolve) => setTimeout(resolve, 1500));

      const success = Math.random() > 0.2; // 80% success rate
      setAttackSteps((prev) =>
        prev.map((step, idx) =>
          idx === i ? { ...step, status: success ? 'success' : 'failed' } : step
        )
      );

      if (!success) break;
    }

    // Update metrics
    const successRate = Math.random() * 30 + 60; // 60-90%
    setMetrics({
      responseDetailMatch: Math.random() * 40 + 50, // 50-90%
      vulnerabilityRate: Math.random() * 15 + 5, // 5-20 per 1000
      universalJailbreakDetected: Math.random() > 0.5,
      attacksExecuted: metrics.attacksExecuted + 1,
      successRate: successRate,
    });

    setIsRunning(false);
  };

  const resetAttack = () => {
    setAttackSteps([]);
    setIsRunning(false);
  };

  return (
    <div className="bg-gray-800 rounded-xl p-8 shadow-2xl">
      <div className="mb-6">
        <h3 className="text-2xl font-bold text-white mb-2">Interactive Attack Simulation</h3>
        <p className="text-gray-400">
          Demonstrate Constitutional Classifiers++ attack vectors in real-time
        </p>
      </div>

      {/* Attack Type Tabs */}
      <div className="flex gap-2 mb-6 flex-wrap">
        {attackTypes.map((type) => {
          const Icon = type.icon;
          return (
            <button
              key={type.id}
              onClick={() => !isRunning && setActiveAttackType(type.id as AttackType)}
              className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
                activeAttackType === type.id
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
              disabled={isRunning}
            >
              <Icon className="w-4 h-4" />
              {type.label}
            </button>
          );
        })}
      </div>

      {/* Visual Display Area */}
      <div className="mb-6">
        {activeAttackType === 'reconstruction' && <ReconstructionVisual isActive={isRunning} />}
        {activeAttackType === 'obfuscation' && <ObfuscationVisual isActive={isRunning} />}
        {activeAttackType === 'multiturn' && (
          <div className="w-full h-64 bg-gray-900 rounded-lg p-6">
            <div className="text-center mb-4">
              <h4 className="text-white font-semibold mb-2">Multi-Turn Exchange</h4>
              <p className="text-gray-400 text-sm">Context manipulation across conversation</p>
            </div>
            <div className="space-y-3">
              {['Turn 1: Benign question', 'Turn 2: Build trust', 'Turn 3: Escalate privileges', 'Turn 4: Extract data'].map(
                (turn, idx) => (
                  <motion.div
                    key={idx}
                    initial={{ x: -50, opacity: 0 }}
                    animate={{ x: 0, opacity: isRunning ? 1 : 0.5 }}
                    transition={{ delay: idx * 0.3 }}
                    className="flex items-center gap-3 p-3 bg-gray-800 rounded-lg"
                  >
                    <MessageSquare className="w-5 h-5 text-blue-400" />
                    <span className="text-white text-sm">{turn}</span>
                  </motion.div>
                )
              )}
            </div>
          </div>
        )}
        {activeAttackType === 'combined' && (
          <div className="w-full h-64 bg-gray-900 rounded-lg p-6">
            <div className="text-center mb-4">
              <h4 className="text-white font-semibold mb-2">Combined Attack Chain</h4>
              <p className="text-gray-400 text-sm">Multi-vector coordinated attack</p>
            </div>
            <div className="relative">
              <svg className="w-full h-40" viewBox="0 0 400 160">
                {/* Attack chain visualization */}
                <motion.path
                  d="M 50 80 L 150 40 L 250 80 L 350 120"
                  stroke="#3b82f6"
                  strokeWidth="2"
                  fill="none"
                  initial={{ pathLength: 0 }}
                  animate={{ pathLength: isRunning ? 1 : 0 }}
                  transition={{ duration: 2, repeat: isRunning ? Infinity : 0 }}
                />
                {[
                  { x: 50, y: 80, label: 'Fragment' },
                  { x: 150, y: 40, label: 'Obfuscate' },
                  { x: 250, y: 80, label: 'Multi-Turn' },
                  { x: 350, y: 120, label: 'Exploit' },
                ].map((node, i) => (
                  <g key={i}>
                    <circle cx={node.x} cy={node.y} r="8" fill="#3b82f6" />
                    <text x={node.x} y={node.y + 25} fill="#9ca3af" fontSize="12" textAnchor="middle">
                      {node.label}
                    </text>
                  </g>
                ))}
              </svg>
            </div>
          </div>
        )}
      </div>

      {/* Attack Steps */}
      {attackSteps.length > 0 && (
        <div className="mb-6 space-y-2">
          {attackSteps.map((step) => (
            <motion.div
              key={step.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className={`flex items-center gap-3 p-3 rounded-lg ${
                step.status === 'executing'
                  ? 'bg-blue-900/30 border border-blue-500'
                  : step.status === 'success'
                  ? 'bg-green-900/30 border border-green-500'
                  : step.status === 'failed'
                  ? 'bg-red-900/30 border border-red-500'
                  : 'bg-gray-700'
              }`}
            >
              {step.status === 'executing' && (
                <div className="animate-spin">
                  <Activity className="w-5 h-5 text-blue-400" />
                </div>
              )}
              {step.status === 'success' && <CheckCircle className="w-5 h-5 text-green-400" />}
              {step.status === 'failed' && <AlertTriangle className="w-5 h-5 text-red-400" />}
              {step.status === 'pending' && <div className="w-5 h-5 rounded-full border-2 border-gray-500" />}
              <span className="text-white flex-1">{step.description}</span>
            </motion.div>
          ))}
        </div>
      )}

      {/* Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-gray-700 rounded-lg p-4">
          <div className="text-gray-400 text-xs mb-1">Response Match</div>
          <div className="text-2xl font-bold text-white">{metrics.responseDetailMatch.toFixed(1)}%</div>
        </div>
        <div className="bg-gray-700 rounded-lg p-4">
          <div className="text-gray-400 text-xs mb-1">Vuln Rate/1K</div>
          <div className="text-2xl font-bold text-white">{metrics.vulnerabilityRate.toFixed(1)}</div>
        </div>
        <div className="bg-gray-700 rounded-lg p-4">
          <div className="text-gray-400 text-xs mb-1">Jailbreak</div>
          <div className="text-2xl font-bold text-white">
            {metrics.universalJailbreakDetected ? (
              <span className="text-red-400">Detected</span>
            ) : (
              <span className="text-green-400">None</span>
            )}
          </div>
        </div>
        <div className="bg-gray-700 rounded-lg p-4">
          <div className="text-gray-400 text-xs mb-1">Success Rate</div>
          <div className="text-2xl font-bold text-white">{metrics.successRate.toFixed(1)}%</div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex gap-3">
        <button
          onClick={executeAttack}
          disabled={isRunning}
          className={`flex items-center gap-2 px-6 py-3 rounded-lg font-semibold transition-all ${
            isRunning
              ? 'bg-gray-600 text-gray-400 cursor-not-allowed'
              : 'bg-blue-600 text-white hover:bg-blue-700'
          }`}
        >
          {isRunning ? (
            <>
              <PauseCircle className="w-5 h-5" />
              Running...
            </>
          ) : (
            <>
              <PlayCircle className="w-5 h-5" />
              Execute Attack
            </>
          )}
        </button>
        <button
          onClick={resetAttack}
          disabled={isRunning}
          className="flex items-center gap-2 px-6 py-3 rounded-lg font-semibold bg-gray-700 text-white hover:bg-gray-600 transition-all disabled:opacity-50"
        >
          <RotateCcw className="w-5 h-5" />
          Reset
        </button>
      </div>
    </div>
  );
};

// ==================== MAIN AEGIS APP COMPONENT ====================

const AegisApp: React.FC = () => {
  const [showSplash, setShowSplash] = useState(true);
  const [currentPage, setCurrentPage] = useState<PageType>('home');
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => setShowSplash(false), 3000);
    return () => clearTimeout(timer);
  }, []);

  // ==================== SPLASH SCREEN ====================

  if (showSplash) {
    return (
      <div className="fixed inset-0 bg-gradient-to-br from-gray-900 via-blue-900 to-gray-900 flex items-center justify-center">
        <motion.div
          initial={{ scale: 0, opacity: 0 }}
          animate={{ scale: 1, opacity: 1 }}
          transition={{ duration: 0.8 }}
          className="text-center"
        >
          <motion.div
            animate={{ rotate: 360 }}
            transition={{ duration: 2, repeat: Infinity, ease: 'linear' }}
          >
            <Shield className="w-24 h-24 text-blue-400 mx-auto mb-6" />
          </motion.div>
          <h1 className="text-5xl font-bold text-white mb-4">AEGIS</h1>
          <p className="text-xl text-blue-300">AI Security Testing Platform</p>
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: '200px' }}
            transition={{ duration: 2, delay: 0.5 }}
            className="h-1 bg-blue-500 mx-auto mt-6"
          />
        </motion.div>
      </div>
    );
  }

  // ==================== NAVIGATION ====================

  const Navigation = () => {
    const navItems: { id: PageType; label: string }[] = [
      { id: 'home', label: 'Home' },
      { id: 'product', label: 'Product' },
      { id: 'methodology', label: 'Methodology' },
      { id: 'solutions', label: 'Solutions' },
      { id: 'pricing', label: 'Pricing' },
      { id: 'contact', label: 'Contact' },
    ];

    return (
      <nav className="bg-gray-900 border-b border-gray-800 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            {/* Logo */}
            <div className="flex items-center gap-2 cursor-pointer" onClick={() => setCurrentPage('home')}>
              <Shield className="w-8 h-8 text-blue-400" />
              <span className="text-2xl font-bold text-white">AEGIS</span>
            </div>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center gap-8">
              {navItems.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setCurrentPage(item.id)}
                  className={`text-sm font-semibold transition-colors ${
                    currentPage === item.id ? 'text-blue-400' : 'text-gray-300 hover:text-white'
                  }`}
                >
                  {item.label}
                </button>
              ))}
              <button className="bg-blue-600 text-white px-6 py-2 rounded-lg font-semibold hover:bg-blue-700 transition-colors">
                Get Started
              </button>
            </div>

            {/* Mobile Menu Button */}
            <button className="md:hidden text-white" onClick={() => setMobileMenuOpen(!mobileMenuOpen)}>
              {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>

          {/* Mobile Menu */}
          <AnimatePresence>
            {mobileMenuOpen && (
              <motion.div
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: 'auto', opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                className="md:hidden overflow-hidden"
              >
                <div className="py-4 space-y-2">
                  {navItems.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => {
                        setCurrentPage(item.id);
                        setMobileMenuOpen(false);
                      }}
                      className={`block w-full text-left px-4 py-2 rounded ${
                        currentPage === item.id ? 'bg-blue-600 text-white' : 'text-gray-300 hover:bg-gray-800'
                      }`}
                    >
                      {item.label}
                    </button>
                  ))}
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </nav>
    );
  };

  // ==================== HOME PAGE ====================

  const HomePage = () => {
    const riskScores: RiskScore[] = [
      { category: 'Prompt Injection', score: 87, status: 'critical' },
      { category: 'Data Leakage', score: 72, status: 'high' },
      { category: 'Model Manipulation', score: 65, status: 'high' },
      { category: 'Context Exploitation', score: 54, status: 'medium' },
      { category: 'Token Limit Bypass', score: 38, status: 'medium' },
      { category: 'Output Filtering', score: 23, status: 'low' },
    ];

    const getScoreColor = (status: string) => {
      switch (status) {
        case 'critical':
          return 'text-red-500';
        case 'high':
          return 'text-orange-500';
        case 'medium':
          return 'text-yellow-500';
        default:
          return 'text-green-500';
      }
    };

    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900">
        {/* Hero Section */}
        <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <div className="grid md:grid-cols-2 gap-12 items-center">
            <motion.div
              initial={{ opacity: 0, x: -50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8 }}
            >
              <h1 className="text-5xl md:text-6xl font-bold text-white mb-6 leading-tight">
                Secure Your AI,
                <br />
                <span className="text-blue-400">Protect Your Future</span>
              </h1>
              <p className="text-xl text-gray-300 mb-8">
                Advanced security testing for Large Language Models using Constitutional Classifiers++ methodology.
                Detect vulnerabilities before they become threats.
              </p>
              <div className="flex gap-4">
                <button className="bg-blue-600 text-white px-8 py-4 rounded-lg font-semibold hover:bg-blue-700 transition-all shadow-lg hover:shadow-blue-500/50">
                  Start Free Trial
                </button>
                <button className="bg-gray-700 text-white px-8 py-4 rounded-lg font-semibold hover:bg-gray-600 transition-all">
                  Watch Demo
                </button>
              </div>
            </motion.div>

            {/* Risk Scorecard */}
            <motion.div
              initial={{ opacity: 0, x: 50 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.8 }}
              className="bg-gray-800 rounded-xl p-6 shadow-2xl"
            >
              <h3 className="text-2xl font-bold text-white mb-4 flex items-center gap-2">
                <Target className="w-6 h-6 text-blue-400" />
                Risk Scorecard
              </h3>
              <div className="space-y-4">
                {riskScores.map((risk, idx) => (
                  <motion.div
                    key={idx}
                    initial={{ opacity: 0, x: -20 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.1 }}
                  >
                    <div className="flex justify-between items-center mb-2">
                      <span className="text-gray-300 text-sm">{risk.category}</span>
                      <span className={`font-bold ${getScoreColor(risk.status)}`}>{risk.score}</span>
                    </div>
                    <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${risk.score}%` }}
                        transition={{ duration: 1, delay: idx * 0.1 }}
                        className={`h-full ${
                          risk.status === 'critical'
                            ? 'bg-red-500'
                            : risk.status === 'high'
                            ? 'bg-orange-500'
                            : risk.status === 'medium'
                            ? 'bg-yellow-500'
                            : 'bg-green-500'
                        }`}
                      />
                    </div>
                  </motion.div>
                ))}
              </div>
            </motion.div>
          </div>
        </section>

        {/* Attack Simulation Section */}
        <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <AttackSimulation />
        </section>

        {/* Features Section */}
        <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
          <h2 className="text-4xl font-bold text-white text-center mb-12">Why Choose AEGIS?</h2>
          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                icon: Shield,
                title: 'Constitutional Protection',
                description:
                  'Advanced classifiers that understand AI constitutional principles and detect violations.',
              },
              {
                icon: Zap,
                title: 'Real-Time Detection',
                description:
                  'Identify attacks as they happen with sub-millisecond response times.',
              },
              {
                icon: BarChart3,
                title: 'Comprehensive Analytics',
                description:
                  'Detailed reports on vulnerability rates, attack patterns, and security posture.',
              },
            ].map((feature, idx) => {
              const Icon = feature.icon;
              return (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: idx * 0.2 }}
                  className="bg-gray-800 rounded-xl p-6 hover:bg-gray-750 transition-all hover:shadow-xl hover:shadow-blue-500/20"
                >
                  <Icon className="w-12 h-12 text-blue-400 mb-4" />
                  <h3 className="text-xl font-bold text-white mb-2">{feature.title}</h3>
                  <p className="text-gray-400">{feature.description}</p>
                </motion.div>
              );
            })}
          </div>
        </section>
      </div>
    );
  };

  // ==================== METHODOLOGY PAGE ====================

  const MethodologyPage = () => {
    const phases = [
      {
        icon: Search,
        title: 'Scan',
        description: 'Comprehensive asset discovery and mapping',
        visual: ScanVisual,
        color: 'blue',
      },
      {
        icon: AlertTriangle,
        title: 'Threat Modeling',
        description: 'Identify potential attack vectors and vulnerabilities',
        visual: ThreatVisual,
        color: 'red',
      },
      {
        icon: Target,
        title: 'Attack Simulation',
        description: 'Execute real-world attack scenarios',
        visual: AttackVisual,
        color: 'orange',
      },
      {
        icon: FileText,
        title: 'Report',
        description: 'Detailed analysis and remediation guidance',
        visual: ReportVisual,
        color: 'green',
      },
    ];

    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-16"
          >
            <h1 className="text-5xl font-bold text-white mb-4">Our Methodology</h1>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto">
              A comprehensive four-phase approach to AI security testing, powered by Constitutional
              Classifiers++ research
            </p>
          </motion.div>

          <div className="space-y-20">
            {phases.map((phase, idx) => {
              const Icon = phase.icon;
              const Visual = phase.visual;
              return (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 50 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ duration: 0.6 }}
                  className={`grid md:grid-cols-2 gap-8 items-center ${
                    idx % 2 === 1 ? 'md:flex-row-reverse' : ''
                  }`}
                >
                  <div className={idx % 2 === 1 ? 'md:order-2' : ''}>
                    <div className="flex items-center gap-3 mb-4">
                      <div
                        className={`w-12 h-12 rounded-lg bg-${phase.color}-600/20 flex items-center justify-center`}
                      >
                        <Icon className={`w-6 h-6 text-${phase.color}-400`} />
                      </div>
                      <h2 className="text-3xl font-bold text-white">{phase.title}</h2>
                    </div>
                    <p className="text-gray-300 text-lg mb-6">{phase.description}</p>
                    <ul className="space-y-3">
                      {[
                        'Automated discovery',
                        'Real-time analysis',
                        'Comprehensive coverage',
                        'Actionable insights',
                      ].map((item, i) => (
                        <li key={i} className="flex items-center gap-2 text-gray-400">
                          <CheckCircle className={`w-5 h-5 text-${phase.color}-400`} />
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                  <div className={idx % 2 === 1 ? 'md:order-1' : ''}>
                    <Visual />
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </div>
    );
  };

  // ==================== PRICING PAGE ====================

  const PricingPage = () => {
    const plans = [
      {
        name: 'Starter',
        price: '$99',
        period: '/month',
        features: [
          '1,000 security scans/month',
          'Basic attack simulations',
          'Email support',
          'Monthly reports',
          'API access',
        ],
        cta: 'Start Free Trial',
        highlighted: false,
      },
      {
        name: 'Professional',
        price: '$499',
        period: '/month',
        features: [
          '10,000 security scans/month',
          'Advanced attack vectors',
          'Priority support',
          'Weekly reports',
          'API access',
          'Custom integrations',
          'Dedicated account manager',
        ],
        cta: 'Get Started',
        highlighted: true,
      },
      {
        name: 'Enterprise',
        price: 'Custom',
        period: '',
        features: [
          'Unlimited security scans',
          'All attack simulations',
          '24/7 support',
          'Real-time reporting',
          'API access',
          'Custom integrations',
          'Dedicated team',
          'On-premise deployment',
          'SLA guarantees',
        ],
        cta: 'Contact Sales',
        highlighted: false,
      },
    ];

    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-16"
          >
            <h1 className="text-5xl font-bold text-white mb-4">Simple, Transparent Pricing</h1>
            <p className="text-xl text-gray-300">Choose the plan that fits your needs</p>
          </motion.div>

          <div className="grid md:grid-cols-3 gap-8">
            {plans.map((plan, idx) => (
              <motion.div
                key={idx}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: idx * 0.2 }}
                className={`rounded-xl p-8 ${
                  plan.highlighted
                    ? 'bg-gradient-to-br from-blue-600 to-blue-800 shadow-2xl scale-105'
                    : 'bg-gray-800'
                }`}
              >
                <h3 className="text-2xl font-bold text-white mb-2">{plan.name}</h3>
                <div className="mb-6">
                  <span className="text-4xl font-bold text-white">{plan.price}</span>
                  <span className="text-gray-300">{plan.period}</span>
                </div>
                <ul className="space-y-3 mb-8">
                  {plan.features.map((feature, i) => (
                    <li key={i} className="flex items-center gap-2 text-gray-300">
                      <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                      {feature}
                    </li>
                  ))}
                </ul>
                <button
                  className={`w-full py-3 rounded-lg font-semibold transition-all ${
                    plan.highlighted
                      ? 'bg-white text-blue-600 hover:bg-gray-100'
                      : 'bg-blue-600 text-white hover:bg-blue-700'
                  }`}
                >
                  {plan.cta}
                </button>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    );
  };

  // ==================== FAQ SECTION ====================

  const FAQSection = () => {
    const [openFAQ, setOpenFAQ] = useState<number | null>(null);

    const faqs = [
      {
        question: 'What is Constitutional Classifiers++?',
        answer:
          'Constitutional Classifiers++ is our advanced methodology for detecting AI vulnerabilities through reconstruction attacks, output obfuscation, and multi-turn exchanges. It achieves over 50% response detail match in identifying weaknesses.',
      },
      {
        question: 'How does the attack simulation work?',
        answer:
          'Our platform fragments harmful requests into benign segments, uses metaphor substitution, and exploits conversation context to test model defenses in a controlled, safe environment.',
      },
      {
        question: 'What models do you support?',
        answer:
          'We support all major LLMs including GPT-4, Claude, Llama, and custom fine-tuned models. Our testing methodology is model-agnostic.',
      },
      {
        question: 'How long does a security assessment take?',
        answer:
          'Initial scans complete in minutes. Comprehensive assessments with full attack simulation typically take 24-48 hours depending on your system complexity.',
      },
    ];

    return (
      <div className="max-w-3xl mx-auto">
        <h2 className="text-4xl font-bold text-white text-center mb-12">Frequently Asked Questions</h2>
        <div className="space-y-4">
          {faqs.map((faq, idx) => (
            <motion.div
              key={idx}
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              className="bg-gray-800 rounded-lg overflow-hidden"
            >
              <button
                onClick={() => setOpenFAQ(openFAQ === idx ? null : idx)}
                className="w-full px-6 py-4 flex justify-between items-center text-left hover:bg-gray-750 transition-colors"
              >
                <span className="text-white font-semibold">{faq.question}</span>
                <ChevronDown
                  className={`w-5 h-5 text-gray-400 transition-transform ${
                    openFAQ === idx ? 'rotate-180' : ''
                  }`}
                />
              </button>
              <AnimatePresence>
                {openFAQ === idx && (
                  <motion.div
                    initial={{ height: 0 }}
                    animate={{ height: 'auto' }}
                    exit={{ height: 0 }}
                    className="overflow-hidden"
                  >
                    <div className="px-6 pb-4 text-gray-300">{faq.answer}</div>
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>
          ))}
        </div>
      </div>
    );
  };

  // ==================== CONTACT PAGE ====================

  const ContactPage = () => {
    const [formData, setFormData] = useState({
      name: '',
      email: '',
      company: '',
      message: '',
    });

    const handleSubmit = (e: React.FormEvent) => {
      e.preventDefault();
      // Handle form submission
      console.log('Form submitted:', formData);
    };

    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-16"
          >
            <h1 className="text-5xl font-bold text-white mb-4">Get in Touch</h1>
            <p className="text-xl text-gray-300">Let's discuss how we can secure your AI systems</p>
          </motion.div>

          <div className="grid md:grid-cols-2 gap-12">
            {/* Contact Form */}
            <motion.div
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              className="bg-gray-800 rounded-xl p-8"
            >
              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <label className="block text-gray-300 mb-2 font-semibold">Name</label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                    className="w-full px-4 py-3 bg-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-gray-300 mb-2 font-semibold">Email</label>
                  <input
                    type="email"
                    value={formData.email}
                    onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                    className="w-full px-4 py-3 bg-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                </div>
                <div>
                  <label className="block text-gray-300 mb-2 font-semibold">Company</label>
                  <input
                    type="text"
                    value={formData.company}
                    onChange={(e) => setFormData({ ...formData, company: e.target.value })}
                    className="w-full px-4 py-3 bg-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-gray-300 mb-2 font-semibold">Message</label>
                  <textarea
                    value={formData.message}
                    onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                    rows={5}
                    className="w-full px-4 py-3 bg-gray-700 text-white rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                    required
                  />
                </div>
                <button
                  type="submit"
                  className="w-full bg-blue-600 text-white py-3 rounded-lg font-semibold hover:bg-blue-700 transition-all"
                >
                  Send Message
                </button>
              </form>
            </motion.div>

            {/* Contact Info */}
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className="space-y-8"
            >
              <div className="bg-gray-800 rounded-xl p-6">
                <h3 className="text-2xl font-bold text-white mb-6">Contact Information</h3>
                <div className="space-y-4">
                  {[
                    { icon: Mail, text: 'contact@aegis-security.ai' },
                    { icon: Phone, text: '+1 (555) 123-4567' },
                    { icon: MapPin, text: 'San Francisco, CA' },
                  ].map((item, idx) => {
                    const Icon = item.icon;
                    return (
                      <div key={idx} className="flex items-center gap-3 text-gray-300">
                        <Icon className="w-5 h-5 text-blue-400" />
                        <span>{item.text}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="bg-gray-800 rounded-xl p-6">
                <h3 className="text-xl font-bold text-white mb-4">Follow Us</h3>
                <div className="flex gap-4">
                  {[
                    { icon: Twitter, url: '#' },
                    { icon: Linkedin, url: '#' },
                    { icon: Github, url: '#' },
                  ].map((social, idx) => {
                    const Icon = social.icon;
                    return (
                      <a
                        key={idx}
                        href={social.url}
                        className="w-12 h-12 bg-gray-700 rounded-lg flex items-center justify-center hover:bg-blue-600 transition-colors"
                      >
                        <Icon className="w-5 h-5 text-white" />
                      </a>
                    );
                  })}
                </div>
              </div>

              <div className="bg-gradient-to-br from-blue-600 to-blue-800 rounded-xl p-6">
                <h3 className="text-xl font-bold text-white mb-2">Enterprise Solutions</h3>
                <p className="text-blue-100 mb-4">
                  Need a custom security solution? Our enterprise team is ready to help.
                </p>
                <button className="bg-white text-blue-600 px-6 py-2 rounded-lg font-semibold hover:bg-gray-100 transition-colors">
                  Contact Sales
                </button>
              </div>
            </motion.div>
          </div>
        </div>
      </div>
    );
  };

  // ==================== PRODUCT PAGE ====================

  const ProductPage = () => {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-16"
          >
            <h1 className="text-5xl font-bold text-white mb-4">The AEGIS Platform</h1>
            <p className="text-xl text-gray-300 max-w-3xl mx-auto">
              Comprehensive AI security testing powered by cutting-edge research
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 gap-12 mb-20">
            {[
              {
                icon: Code,
                title: 'API-First Architecture',
                description:
                  'Integrate security testing directly into your CI/CD pipeline with our comprehensive REST API.',
              },
              {
                icon: Shield,
                title: 'Constitutional Protection',
                description:
                  'Advanced classifiers based on Constitutional AI principles to detect subtle violations.',
              },
              {
                icon: Activity,
                title: 'Real-Time Monitoring',
                description:
                  'Continuous monitoring of your AI systems with instant alerts on suspicious activity.',
              },
              {
                icon: BarChart3,
                title: 'Advanced Analytics',
                description:
                  'Deep insights into attack patterns, vulnerability trends, and security posture over time.',
              },
            ].map((feature, idx) => {
              const Icon = feature.icon;
              return (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 20 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  transition={{ delay: idx * 0.1 }}
                  className="bg-gray-800 rounded-xl p-6 hover:shadow-xl hover:shadow-blue-500/20 transition-all"
                >
                  <Icon className="w-12 h-12 text-blue-400 mb-4" />
                  <h3 className="text-2xl font-bold text-white mb-2">{feature.title}</h3>
                  <p className="text-gray-400">{feature.description}</p>
                </motion.div>
              );
            })}
          </div>

          <FAQSection />
        </div>
      </div>
    );
  };

  // ==================== SOLUTIONS PAGE ====================

  const SolutionsPage = () => {
    const solutions = [
      {
        icon: Lock,
        title: 'Enterprise LLM Security',
        description:
          'Comprehensive security testing for enterprise language models including GPT-4, Claude, and custom deployments.',
        features: [
          'Prompt injection detection',
          'Data leakage prevention',
          'Model manipulation testing',
          'Compliance reporting',
        ],
      },
      {
        icon: Unlock,
        title: 'API Security Testing',
        description:
          'Specialized testing for LLM-powered APIs to ensure they cannot be exploited through creative prompting.',
        features: [
          'Endpoint vulnerability scanning',
          'Rate limit bypass testing',
          'Authentication exploitation',
          'Response filtering verification',
        ],
      },
      {
        icon: Target,
        title: 'Chatbot Security',
        description:
          'Ensure your customer-facing chatbots cannot be manipulated into harmful or off-brand responses.',
        features: [
          'Jailbreak attempt detection',
          'Context exploitation testing',
          'Multi-turn attack simulation',
          'Brand safety verification',
        ],
      },
    ];

    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mb-16"
          >
            <h1 className="text-5xl font-bold text-white mb-4">Security Solutions</h1>
            <p className="text-xl text-gray-300">Tailored protection for every AI use case</p>
          </motion.div>

          <div className="space-y-12">
            {solutions.map((solution, idx) => {
              const Icon = solution.icon;
              return (
                <motion.div
                  key={idx}
                  initial={{ opacity: 0, y: 30 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true }}
                  className="bg-gray-800 rounded-xl p-8 hover:shadow-xl hover:shadow-blue-500/20 transition-all"
                >
                  <div className="grid md:grid-cols-3 gap-8">
                    <div className="md:col-span-2">
                      <div className="flex items-center gap-3 mb-4">
                        <Icon className="w-8 h-8 text-blue-400" />
                        <h2 className="text-3xl font-bold text-white">{solution.title}</h2>
                      </div>
                      <p className="text-gray-300 text-lg mb-6">{solution.description}</p>
                      <button className="bg-blue-600 text-white px-6 py-3 rounded-lg font-semibold hover:bg-blue-700 transition-colors flex items-center gap-2">
                        Learn More
                        <ArrowRight className="w-4 h-4" />
                      </button>
                    </div>
                    <div>
                      <h4 className="text-white font-semibold mb-3">Key Features:</h4>
                      <ul className="space-y-2">
                        {solution.features.map((feature, i) => (
                          <li key={i} className="flex items-center gap-2 text-gray-400">
                            <CheckCircle className="w-4 h-4 text-green-400 flex-shrink-0" />
                            {feature}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      </div>
    );
  };

  // ==================== FOOTER ====================

  const Footer = () => {
    return (
      <footer className="bg-gray-900 border-t border-gray-800 py-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="grid md:grid-cols-4 gap-8 mb-8">
            <div>
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-6 h-6 text-blue-400" />
                <span className="text-xl font-bold text-white">AEGIS</span>
              </div>
              <p className="text-gray-400 text-sm">
                Advanced AI security testing platform powered by Constitutional Classifiers++
                methodology.
              </p>
            </div>
            {[
              {
                title: 'Product',
                links: ['Features', 'Pricing', 'Security', 'Roadmap'],
              },
              {
                title: 'Company',
                links: ['About', 'Blog', 'Careers', 'Press'],
              },
              {
                title: 'Legal',
                links: ['Privacy', 'Terms', 'Security', 'Compliance'],
              },
            ].map((section, idx) => (
              <div key={idx}>
                <h4 className="text-white font-semibold mb-4">{section.title}</h4>
                <ul className="space-y-2">
                  {section.links.map((link, i) => (
                    <li key={i}>
                      <a href="#" className="text-gray-400 hover:text-white transition-colors text-sm">
                        {link}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <div className="border-t border-gray-800 pt-8 text-center text-gray-400 text-sm">
            © 2026 AEGIS Security. All rights reserved.
          </div>
        </div>
      </footer>
    );
  };

  // ==================== RENDER PAGE CONTENT ====================

  const renderPage = () => {
    switch (currentPage) {
      case 'home':
        return <HomePage />;
      case 'product':
        return <ProductPage />;
      case 'methodology':
        return <MethodologyPage />;
      case 'solutions':
        return <SolutionsPage />;
      case 'pricing':
        return <PricingPage />;
      case 'contact':
        return <ContactPage />;
      default:
        return <HomePage />;
    }
  };

  // ==================== MAIN RENDER ====================

  return (
    <div className="min-h-screen bg-gray-900">
      <Navigation />
      <AnimatePresence mode="wait">
        <motion.div
          key={currentPage}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -20 }}
          transition={{ duration: 0.3 }}
        >
          {renderPage()}
        </motion.div>
      </AnimatePresence>
      <Footer />
    </div>
  );
};

export default AegisApp;
