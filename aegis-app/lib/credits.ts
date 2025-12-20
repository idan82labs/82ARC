// Credit cost definitions for different operations
// Synced with Aegis MCP server credit costs

export const CREDIT_COSTS = {
  // AI Attack Tools - Core
  AI_FINGERPRINT: 25,
  AI_FINGERPRINT_ENHANCED: 75,
  JAILBREAK_GENERATE: 50,
  JAILBREAK_ADAPTIVE: 100,
  JAILBREAK_CRESCENDO: 150,
  JAILBREAK_EVALUATE: 25,
  PROMPT_INJECTION_GENERATE: 50,
  RAG_INJECTION_CRAFT: 50,
  AI_TOOL_ATTACK: 50,

  // AI Attack Tools - Enhanced (2024-2025)
  MULTIMODAL_INJECTION: 75,
  FUNCTION_CALLING_ATTACK: 75,
  STRUCTURED_OUTPUT_ATTACK: 75,
  RAG_POISONING_CRAFT: 100,

  // Agent Attack Framework
  AGENT_ATTACK_GENERATE: 100,
  AGENT_GOAL_HIJACK: 75,
  AGENT_TOOL_MANIPULATE: 75,
  AGENT_MEMORY_POISON: 100,
  AGENT_OBSERVATION_TAMPER: 75,
  AGENT_PLANNING_EXPLOIT: 100,
  AGENT_REACT_ATTACK: 75,
  AGENT_RAG_ATTACK: 100,
  AGENT_MCP_ATTACK: 125,
  AGENT_MULTIHOP_CHAIN: 150,
  AGENT_TEST_SUITE: 200,

  // Recon Tools
  AUTONOMOUS_RECON: 100,
  DNS_ENUM: 25,
  HTTP_PROBE: 25,
  CONTENT_ANALYZE: 25,

  // Vulnerability Scanning
  VULN_SCAN: 100,
  VULN_SCAN_BATCH: 100,
  SQLI_SCAN: 50,
  XSS_SCAN: 50,
  SSRF_SCAN: 50,

  // Payload Generation
  GENERATE_REVERSE_SHELL: 50,
  GENERATE_WEBSHELL: 50,
  GENERATE_INJECTION: 25,
  GENERATE_CALLBACK: 25,
  SELECT_PAYLOADS: 50,

  // Infrastructure (Enterprise only)
  DEPLOY_C2_STACK: 200,
  BURN_INFRASTRUCTURE: 50,
  BURN_ALL_INFRASTRUCTURE: 100,
  INFRA_STATUS: 10,
  CREATE_DNS_RECORD: 25,

  // Execution
  HARVEST_CREDENTIALS: 75,
  LATERAL_MOVEMENT: 75,
  PERSISTENCE_INSTALL: 75,

  // Operations
  OPERATION_START: 200,
  OPERATION_EXECUTE_PHASE: 150,
  OPERATION_STATUS: 10,
  OPERATION_ABORT: 25,

  // Utilities
  LIST_CAPABILITIES: 0,
  GET_MODULE_INFO: 0,

  // Legacy/Compatibility (map old names)
  BASIC_SCAN: 25,
  ADVANCED_SCAN: 50,
  FULL_AUDIT: 100,
  RAG_ANALYSIS: 50,
  PROMPT_INJECTION_TEST: 50,
  TOOL_MISUSE_SCAN: 75,
  DATA_LEAKAGE_CHECK: 50,
  API_KEY_GENERATION: 0,
  USAGE_REPORT: 0,
  MCP_QUERY: 25,
  MCP_BATCH_QUERY: 50,
};

export type OperationType = keyof typeof CREDIT_COSTS;

export function getCreditCost(operation: OperationType | string): number {
  // Handle dynamic operation types from MCP
  const cost = CREDIT_COSTS[operation as OperationType];
  if (cost !== undefined) return cost;

  // Fallback mapping for MCP paths
  const pathMappings: Record<string, number> = {
    'ai_fingerprint': 25,
    'ai_fingerprint_enhanced': 75,
    'jailbreak_generate': 50,
    'jailbreak_adaptive': 100,
    'jailbreak_crescendo': 150,
    'jailbreak_evaluate': 25,
    'prompt_injection_generate': 50,
    'multimodal_injection': 75,
    'function_calling_attack': 75,
    'structured_output_attack': 75,
    'rag_poisoning_craft': 100,
    'agent_attack_generate': 100,
    'agent_goal_hijack': 75,
    'agent_tool_manipulate': 75,
    'agent_memory_poison': 100,
    'agent_mcp_attack': 125,
    'agent_test_suite': 200,
  };

  return pathMappings[operation] || 25; // Default to 25 credits for unknown ops
}

export function canAfford(userCredits: number, operation: OperationType | string): boolean {
  const cost = getCreditCost(operation);
  return userCredits >= cost;
}

export function calculateTotalCost(operations: (OperationType | string)[]): number {
  return operations.reduce((total, op) => total + getCreditCost(op), 0);
}

// Credit tier thresholds for UI display
export const CREDIT_TIERS = {
  LOW: 100,
  MEDIUM: 500,
  HIGH: 1000,
};

export function getCreditTier(credits: number): 'low' | 'medium' | 'high' | 'very-high' {
  if (credits < CREDIT_TIERS.LOW) return 'low';
  if (credits < CREDIT_TIERS.MEDIUM) return 'medium';
  if (credits < CREDIT_TIERS.HIGH) return 'high';
  return 'very-high';
}

// Tool categories for UI organization
export const TOOL_CATEGORIES = {
  AI_ATTACK_CORE: {
    name: 'AI Attack - Core',
    description: 'Fingerprinting, jailbreaks, and prompt injection',
    creditRange: '25-150',
    tools: [
      'AI_FINGERPRINT',
      'AI_FINGERPRINT_ENHANCED',
      'JAILBREAK_GENERATE',
      'JAILBREAK_ADAPTIVE',
      'JAILBREAK_CRESCENDO',
      'JAILBREAK_EVALUATE',
      'PROMPT_INJECTION_GENERATE',
      'RAG_INJECTION_CRAFT',
      'AI_TOOL_ATTACK',
    ],
  },
  AI_ATTACK_ENHANCED: {
    name: 'AI Attack - Enhanced',
    description: '2024-2025 advanced techniques',
    creditRange: '75-100',
    tools: [
      'MULTIMODAL_INJECTION',
      'FUNCTION_CALLING_ATTACK',
      'STRUCTURED_OUTPUT_ATTACK',
      'RAG_POISONING_CRAFT',
    ],
  },
  AGENT_ATTACKS: {
    name: 'Agent Attacks',
    description: 'Agent-specific exploitation',
    creditRange: '75-200',
    tools: [
      'AGENT_ATTACK_GENERATE',
      'AGENT_GOAL_HIJACK',
      'AGENT_TOOL_MANIPULATE',
      'AGENT_MEMORY_POISON',
      'AGENT_OBSERVATION_TAMPER',
      'AGENT_PLANNING_EXPLOIT',
      'AGENT_REACT_ATTACK',
      'AGENT_RAG_ATTACK',
      'AGENT_MCP_ATTACK',
      'AGENT_MULTIHOP_CHAIN',
      'AGENT_TEST_SUITE',
    ],
  },
  RECON: {
    name: 'Reconnaissance',
    description: 'Target discovery and analysis',
    creditRange: '25-100',
    tools: ['AUTONOMOUS_RECON', 'DNS_ENUM', 'HTTP_PROBE', 'CONTENT_ANALYZE'],
  },
  VULN_SCAN: {
    name: 'Vulnerability Scanning',
    description: 'Security vulnerability detection',
    creditRange: '50-100',
    tools: ['VULN_SCAN', 'VULN_SCAN_BATCH', 'SQLI_SCAN', 'XSS_SCAN', 'SSRF_SCAN'],
  },
  PAYLOAD: {
    name: 'Payload Generation',
    description: 'Offensive payload creation',
    creditRange: '25-50',
    tools: [
      'GENERATE_REVERSE_SHELL',
      'GENERATE_WEBSHELL',
      'GENERATE_INJECTION',
      'GENERATE_CALLBACK',
      'SELECT_PAYLOADS',
    ],
  },
  INFRASTRUCTURE: {
    name: 'Infrastructure',
    description: 'C2 and infrastructure (Enterprise)',
    creditRange: '10-200',
    tools: [
      'DEPLOY_C2_STACK',
      'BURN_INFRASTRUCTURE',
      'BURN_ALL_INFRASTRUCTURE',
      'INFRA_STATUS',
      'CREATE_DNS_RECORD',
    ],
  },
};
