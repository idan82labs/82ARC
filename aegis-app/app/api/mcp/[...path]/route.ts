import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getUserByClerkId, logUsage, updateUserCredits } from '@/lib/supabase';
import { getCreditCost } from '@/lib/credits';

// This is a proxy endpoint to the NightOwl MCP server
// It handles credit deduction and usage logging

const MCP_BASE_URL = process.env.NIGHTOWL_MCP_URL || 'http://localhost:8000';

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
        Authorization: `Bearer ${process.env.NIGHTOWL_MCP_API_KEY}`,
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

function determineOperation(path: string): any {
  // Map MCP paths to operation types
  if (path.includes('scan')) return 'BASIC_SCAN';
  if (path.includes('query')) return 'MCP_QUERY';
  if (path.includes('batch')) return 'MCP_BATCH_QUERY';
  return 'MCP_QUERY'; // default
}
