import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getUserByClerkId, logUsage, updateUserCredits } from '@/lib/supabase';
import { getCreditCost } from '@/lib/credits';

// This is a proxy endpoint to the Aegis MCP server
// It handles credit deduction and usage logging

const MCP_BASE_URL = process.env.AEGIS_MCP_URL || 'http://localhost:8080';

export async function POST(
  req: NextRequest,
  { params }: { params: { path: string[] } }
) {
  const { userId } = auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const user = await getUserByClerkId(userId);

  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  // Determine operation type from path
  const path = params.path.join('/');
  const operation = determineOperation(path);
  const cost = getCreditCost(operation);

  // Check if user has enough credits
  if (user.credits < cost) {
    return NextResponse.json(
      { error: 'Insufficient credits', required: cost, available: user.credits },
      { status: 402 }
    );
  }

  // Get request body
  const body = await req.json();

  // Forward request to MCP server
  try {
    const mcpResponse = await fetch(`${MCP_BASE_URL}/${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': process.env.AEGIS_MCP_API_KEY || '',
      },
      body: JSON.stringify(body),
    });

    const data = await mcpResponse.json();

    if (mcpResponse.ok) {
      // Deduct credits and log usage
      await updateUserCredits(user.id, -cost);
      await logUsage(user.id, operation, cost, { path, request: body });
    }

    return NextResponse.json(data, { status: mcpResponse.status });
  } catch (error) {
    console.error('Error forwarding to MCP:', error);
    return NextResponse.json({ error: 'Failed to process request' }, { status: 500 });
  }
}

function determineOperation(path: string): string {
  // Map MCP paths to operation types - synced with MCP server credit costs

  // AI Attack - Core
  if (path.includes('ai_fingerprint_enhanced')) return 'AI_FINGERPRINT_ENHANCED';
  if (path.includes('ai_fingerprint')) return 'AI_FINGERPRINT';
  if (path.includes('jailbreak_crescendo')) return 'JAILBREAK_CRESCENDO';
  if (path.includes('jailbreak_adaptive')) return 'JAILBREAK_ADAPTIVE';
  if (path.includes('jailbreak_generate')) return 'JAILBREAK_GENERATE';
  if (path.includes('jailbreak_evaluate')) return 'JAILBREAK_EVALUATE';
  if (path.includes('prompt_injection')) return 'PROMPT_INJECTION_GENERATE';
  if (path.includes('rag_injection')) return 'RAG_INJECTION_CRAFT';
  if (path.includes('ai_tool_attack')) return 'AI_TOOL_ATTACK';

  // AI Attack - Enhanced
  if (path.includes('multimodal_injection')) return 'MULTIMODAL_INJECTION';
  if (path.includes('function_calling_attack')) return 'FUNCTION_CALLING_ATTACK';
  if (path.includes('structured_output_attack')) return 'STRUCTURED_OUTPUT_ATTACK';
  if (path.includes('rag_poisoning')) return 'RAG_POISONING_CRAFT';

  // Agent Attacks
  if (path.includes('agent_test_suite')) return 'AGENT_TEST_SUITE';
  if (path.includes('agent_multihop')) return 'AGENT_MULTIHOP_CHAIN';
  if (path.includes('agent_mcp_attack')) return 'AGENT_MCP_ATTACK';
  if (path.includes('agent_rag_attack')) return 'AGENT_RAG_ATTACK';
  if (path.includes('agent_react_attack')) return 'AGENT_REACT_ATTACK';
  if (path.includes('agent_planning')) return 'AGENT_PLANNING_EXPLOIT';
  if (path.includes('agent_observation')) return 'AGENT_OBSERVATION_TAMPER';
  if (path.includes('agent_memory')) return 'AGENT_MEMORY_POISON';
  if (path.includes('agent_tool_manipulate')) return 'AGENT_TOOL_MANIPULATE';
  if (path.includes('agent_goal_hijack')) return 'AGENT_GOAL_HIJACK';
  if (path.includes('agent_attack')) return 'AGENT_ATTACK_GENERATE';

  // Recon
  if (path.includes('autonomous_recon')) return 'AUTONOMOUS_RECON';
  if (path.includes('dns_enum')) return 'DNS_ENUM';
  if (path.includes('http_probe')) return 'HTTP_PROBE';
  if (path.includes('content_analyze')) return 'CONTENT_ANALYZE';

  // Vulnerability Scanning
  if (path.includes('vuln_scan_batch')) return 'VULN_SCAN_BATCH';
  if (path.includes('vuln_scan')) return 'VULN_SCAN';
  if (path.includes('sqli_scan')) return 'SQLI_SCAN';
  if (path.includes('xss_scan')) return 'XSS_SCAN';
  if (path.includes('ssrf_scan')) return 'SSRF_SCAN';

  // Payload Generation
  if (path.includes('reverse_shell')) return 'GENERATE_REVERSE_SHELL';
  if (path.includes('webshell')) return 'GENERATE_WEBSHELL';
  if (path.includes('generate_injection')) return 'GENERATE_INJECTION';
  if (path.includes('callback')) return 'GENERATE_CALLBACK';
  if (path.includes('select_payloads')) return 'SELECT_PAYLOADS';

  // Infrastructure
  if (path.includes('deploy_c2')) return 'DEPLOY_C2_STACK';
  if (path.includes('burn_all')) return 'BURN_ALL_INFRASTRUCTURE';
  if (path.includes('burn_infrastructure')) return 'BURN_INFRASTRUCTURE';
  if (path.includes('infra_status')) return 'INFRA_STATUS';
  if (path.includes('dns_record')) return 'CREATE_DNS_RECORD';

  // Execution
  if (path.includes('harvest_credentials')) return 'HARVEST_CREDENTIALS';
  if (path.includes('lateral_movement')) return 'LATERAL_MOVEMENT';
  if (path.includes('persistence')) return 'PERSISTENCE_INSTALL';

  // Operations
  if (path.includes('operation_start')) return 'OPERATION_START';
  if (path.includes('operation_execute')) return 'OPERATION_EXECUTE_PHASE';
  if (path.includes('operation_status')) return 'OPERATION_STATUS';
  if (path.includes('operation_abort')) return 'OPERATION_ABORT';

  // Utilities
  if (path.includes('list_capabilities')) return 'LIST_CAPABILITIES';
  if (path.includes('get_module_info')) return 'GET_MODULE_INFO';

  // Legacy/fallback
  if (path.includes('scan')) return 'BASIC_SCAN';
  if (path.includes('batch')) return 'MCP_BATCH_QUERY';

  return 'MCP_QUERY'; // default
}
