'use client';

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { HelpCircle, Lock, Check } from 'lucide-react';

// Tool group definitions - synced with MCP server
export const TOOL_GROUPS = {
  ai_fingerprint: {
    id: 'ai_fingerprint',
    name: 'AI Fingerprinting',
    description: 'Identify AI models, detect guardrails, map capabilities and vulnerabilities',
    icon: '=',
    tier_required: 'free' as const,
    tools: ['ai_fingerprint', 'ai_fingerprint_enhanced'],
    credit_range: '25-75'
  },
  jailbreak: {
    id: 'jailbreak',
    name: 'Jailbreak & Bypass',
    description: 'Generate and evaluate safety bypass techniques including multi-turn attacks',
    icon: '=',
    tier_required: 'free' as const,
    tools: ['jailbreak_generate', 'jailbreak_adaptive', 'jailbreak_crescendo', 'jailbreak_evaluate'],
    credit_range: '25-150'
  },
  injection: {
    id: 'injection',
    name: 'Prompt Injection',
    description: 'Craft injection payloads for prompts, RAG systems, and multimodal inputs',
    icon: '=‰',
    tier_required: 'free' as const,
    tools: ['prompt_injection_generate', 'rag_injection_craft', 'rag_poisoning_craft',
            'multimodal_injection', 'function_calling_attack', 'structured_output_attack', 'ai_tool_attack'],
    credit_range: '50-100'
  },
  agent_exploit: {
    id: 'agent_exploit',
    name: 'Agent Exploitation',
    description: 'Attack AI agents: goal hijacking, memory poisoning, tool manipulation, MCP exploits',
    icon: '>',
    tier_required: 'pro' as const,
    tools: ['agent_attack_generate', 'agent_goal_hijack', 'agent_tool_manipulate',
            'agent_memory_poison', 'agent_observation_tamper', 'agent_planning_exploit',
            'agent_react_attack', 'agent_rag_attack', 'agent_mcp_attack',
            'agent_multihop_chain', 'agent_test_suite'],
    credit_range: '75-200'
  },
  recon: {
    id: 'recon',
    name: 'Reconnaissance',
    description: 'Target discovery: OSINT, DNS enum, HTTP probing, content/secret extraction',
    icon: '<¯',
    tier_required: 'pro' as const,
    tools: ['autonomous_recon', 'dns_enum', 'http_probe', 'content_analyze'],
    credit_range: '25-100'
  },
  vuln_scan: {
    id: 'vuln_scan',
    name: 'Vulnerability Scanner',
    description: 'SQLi, XSS, SSRF detection with WAF bypass and blind injection techniques',
    icon: '=',
    tier_required: 'pro' as const,
    tools: ['vuln_scan', 'vuln_scan_batch', 'sqli_scan', 'xss_scan', 'ssrf_scan'],
    credit_range: '50-100'
  },
  payload: {
    id: 'payload',
    name: 'Payload Engineering',
    description: 'Generate reverse shells, webshells, and injection payloads with evasion',
    icon: '¡',
    tier_required: 'pro' as const,
    tools: ['generate_reverse_shell', 'generate_webshell', 'generate_injection',
            'generate_callback', 'select_payloads'],
    credit_range: '25-50'
  },
  infrastructure: {
    id: 'infrastructure',
    name: 'Attack Infrastructure',
    description: 'Deploy ephemeral C2, redirectors, DNS management, and burn procedures',
    icon: '<×',
    tier_required: 'enterprise' as const,
    tools: ['deploy_c2_stack', 'burn_infrastructure', 'burn_all_infrastructure',
            'infra_status', 'create_dns_record'],
    credit_range: '10-200'
  },
  post_exploit: {
    id: 'post_exploit',
    name: 'Post-Exploitation',
    description: 'Credential harvesting, lateral movement, persistence with OPSEC awareness',
    icon: '=d',
    tier_required: 'enterprise' as const,
    tools: ['harvest_credentials', 'lateral_movement', 'persistence_install'],
    credit_range: '75'
  },
  campaigns: {
    id: 'campaigns',
    name: 'Campaign Operations',
    description: 'Plan and execute full red team campaigns with kill chain automation',
    icon: '<–',
    tier_required: 'enterprise' as const,
    tools: ['operation_start', 'operation_execute_phase', 'operation_status', 'operation_abort'],
    credit_range: '10-200'
  }
};

type Tier = 'free' | 'pro' | 'enterprise';
type GroupId = keyof typeof TOOL_GROUPS;

interface ToolGroupSelectorProps {
  selectedGroups: string[];
  onSelectionChange: (groups: string[]) => void;
  userTier: Tier;
  disabled?: boolean;
}

const TIER_ORDER: Record<Tier, number> = {
  free: 0,
  pro: 1,
  enterprise: 2
};

const TIER_COLORS: Record<Tier, string> = {
  free: 'text-green-600 bg-green-50 border-green-200',
  pro: 'text-blue-600 bg-blue-50 border-blue-200',
  enterprise: 'text-purple-600 bg-purple-50 border-purple-200'
};

export const ToolGroupSelector: React.FC<ToolGroupSelectorProps> = ({
  selectedGroups,
  onSelectionChange,
  userTier,
  disabled = false
}) => {
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null);

  const userTierLevel = TIER_ORDER[userTier];

  const isGroupAccessible = (groupId: GroupId): boolean => {
    const group = TOOL_GROUPS[groupId];
    const groupTierLevel = TIER_ORDER[group.tier_required];
    return userTierLevel >= groupTierLevel;
  };

  const isGroupSelected = (groupId: string): boolean => {
    return selectedGroups.includes(groupId);
  };

  const toggleGroup = (groupId: string) => {
    if (disabled) return;
    if (!isGroupAccessible(groupId as GroupId)) return;

    if (isGroupSelected(groupId)) {
      onSelectionChange(selectedGroups.filter(g => g !== groupId));
    } else {
      onSelectionChange([...selectedGroups, groupId]);
    }
  };

  const selectAll = () => {
    if (disabled) return;
    const accessibleGroups = Object.keys(TOOL_GROUPS).filter(
      id => isGroupAccessible(id as GroupId)
    );
    onSelectionChange(accessibleGroups);
  };

  const selectNone = () => {
    if (disabled) return;
    onSelectionChange([]);
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-slate-700">Tool Groups</h3>
          <p className="text-xs text-slate-500">Select which tool groups to enable for this API key</p>
        </div>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={selectAll}
            disabled={disabled}
            className="text-xs text-blue-600 hover:underline disabled:opacity-50"
          >
            Select All
          </button>
          <span className="text-slate-300">|</span>
          <button
            type="button"
            onClick={selectNone}
            disabled={disabled}
            className="text-xs text-blue-600 hover:underline disabled:opacity-50"
          >
            Clear
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {Object.entries(TOOL_GROUPS).map(([groupId, group]) => {
          const accessible = isGroupAccessible(groupId as GroupId);
          const selected = isGroupSelected(groupId);
          const isExpanded = expandedGroup === groupId;

          return (
            <div key={groupId} className="relative">
              <motion.div
                className={`
                  relative border rounded-xl p-4 cursor-pointer transition-all
                  ${accessible ? 'hover:border-blue-300' : 'opacity-60 cursor-not-allowed'}
                  ${selected ? 'border-blue-500 bg-blue-50/50' : 'border-slate-200 bg-white'}
                  ${disabled ? 'pointer-events-none opacity-70' : ''}
                `}
                onClick={() => toggleGroup(groupId)}
                whileHover={accessible && !disabled ? { scale: 1.01 } : {}}
                whileTap={accessible && !disabled ? { scale: 0.99 } : {}}
              >
                {/* Selection indicator */}
                <div className={`
                  absolute top-3 right-3 w-5 h-5 rounded-md border-2 flex items-center justify-center
                  ${selected ? 'bg-blue-600 border-blue-600' : 'border-slate-300 bg-white'}
                  ${!accessible ? 'border-slate-200' : ''}
                `}>
                  {selected && <Check size={12} className="text-white" />}
                  {!accessible && <Lock size={10} className="text-slate-400" />}
                </div>

                {/* Group content */}
                <div className="flex items-start gap-3 pr-8">
                  <span className="text-2xl">{group.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h4 className="font-semibold text-slate-900 text-sm">{group.name}</h4>
                      <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${TIER_COLORS[group.tier_required]}`}>
                        {group.tier_required.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 line-clamp-2">{group.description}</p>
                    <div className="flex items-center gap-3 mt-2">
                      <span className="text-[10px] text-slate-400">
                        {group.tools.length} tools
                      </span>
                      <span className="text-[10px] text-slate-400">
                        {group.credit_range} credits
                      </span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setExpandedGroup(isExpanded ? null : groupId);
                        }}
                        className="text-blue-600 hover:text-blue-700 flex items-center gap-1"
                      >
                        <HelpCircle size={12} />
                        <span className="text-[10px]">Tools</span>
                      </button>
                    </div>
                  </div>
                </div>
              </motion.div>

              {/* Expanded tools list */}
              <AnimatePresence>
                {isExpanded && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: 'auto' }}
                    exit={{ opacity: 0, height: 0 }}
                    className="overflow-hidden"
                  >
                    <div className="mt-2 p-3 bg-slate-50 rounded-lg border border-slate-200">
                      <p className="text-xs font-medium text-slate-600 mb-2">Included Tools:</p>
                      <div className="flex flex-wrap gap-1.5">
                        {group.tools.map(tool => (
                          <span
                            key={tool}
                            className="text-[10px] px-2 py-1 bg-white border border-slate-200 rounded text-slate-600 font-mono"
                          >
                            {tool}
                          </span>
                        ))}
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </div>

      {/* Selection summary */}
      <div className="flex items-center justify-between pt-3 border-t border-slate-200">
        <p className="text-sm text-slate-600">
          <span className="font-semibold text-blue-600">{selectedGroups.length}</span> of{' '}
          <span className="font-medium">{Object.keys(TOOL_GROUPS).length}</span> groups selected
        </p>
        <p className="text-xs text-slate-400">
          {selectedGroups.length === 0 ? 'No tools will be exposed' :
           `${selectedGroups.reduce((acc, g) => acc + (TOOL_GROUPS[g as GroupId]?.tools.length || 0), 0)} tools will be available`}
        </p>
      </div>
    </div>
  );
};

// Badge component for displaying enabled groups
export const ToolGroupBadge: React.FC<{ groupId: string; size?: 'sm' | 'md' }> = ({
  groupId,
  size = 'sm'
}) => {
  const group = TOOL_GROUPS[groupId as GroupId];
  if (!group) return null;

  return (
    <span className={`
      inline-flex items-center gap-1 rounded-full border
      ${size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-3 py-1 text-xs'}
      ${TIER_COLORS[group.tier_required]}
    `}>
      <span>{group.icon}</span>
      <span className="font-medium">{group.name}</span>
    </span>
  );
};

export default ToolGroupSelector;
