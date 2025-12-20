import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getUserByClerkId, getAPIKeys, createAPIKey, deleteAPIKey, updateAPIKey } from '@/lib/supabase';
import crypto from 'crypto';

// Valid tool group IDs that can be selected
const VALID_TOOL_GROUPS = [
  'ai_fingerprint',
  'jailbreak',
  'injection',
  'agent_exploit',
  'recon',
  'vuln_scan',
  'payload',
  'infrastructure',
  'post_exploit',
  'campaigns'
];

// GET - List all API keys for the user
export async function GET(req: NextRequest) {
  const { userId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Get user by Clerk ID to get internal UUID
  const user = await getUserByClerkId(userId);
  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  // Use internal user.id (UUID) to fetch API keys
  const keys = await getAPIKeys(user.id);

  return NextResponse.json({ keys });
}

// POST - Create a new API key
export async function POST(req: NextRequest) {
  const { userId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { name, tool_groups } = await req.json();

  if (!name) {
    return NextResponse.json({ error: 'Name is required' }, { status: 400 });
  }

  // Validate tool_groups if provided
  let validatedToolGroups: string[] | null = null;
  if (tool_groups !== undefined && tool_groups !== null) {
    if (!Array.isArray(tool_groups)) {
      return NextResponse.json({ error: 'tool_groups must be an array' }, { status: 400 });
    }
    // Filter to only valid group IDs
    validatedToolGroups = tool_groups.filter((g: string) => VALID_TOOL_GROUPS.includes(g));
    if (validatedToolGroups.length === 0) {
      validatedToolGroups = null; // Empty selection means all tier-allowed groups
    }
  }

  // Get user by Clerk ID to get internal UUID
  const user = await getUserByClerkId(userId);
  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  // Generate a random API key
  const key = `sk_${crypto.randomBytes(32).toString('hex')}`;
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  const keyPrefix = key.substring(0, 11); // "sk_" + first 8 chars

  // Use helper function that uses internal user.id
  const apiKey = await createAPIKey(user.id, name, keyHash, keyPrefix, validatedToolGroups);

  if (!apiKey) {
    return NextResponse.json({ error: 'Failed to create API key' }, { status: 500 });
  }

  // Return the actual key only once (it won't be stored)
  return NextResponse.json({
    key,
    id: apiKey.id,
    name: apiKey.name,
    tool_groups: apiKey.tool_groups
  });
}

// PATCH - Update an API key (name or tool_groups)
export async function PATCH(req: NextRequest) {
  const { userId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { id, name, tool_groups } = await req.json();

  if (!id) {
    return NextResponse.json({ error: 'Key ID is required' }, { status: 400 });
  }

  // Build updates object
  const updates: { name?: string; tool_groups?: string[] | null } = {};

  if (name !== undefined) {
    if (typeof name !== 'string' || name.trim() === '') {
      return NextResponse.json({ error: 'Invalid name' }, { status: 400 });
    }
    updates.name = name.trim();
  }

  if (tool_groups !== undefined) {
    if (tool_groups === null) {
      updates.tool_groups = null; // Reset to all tier-allowed groups
    } else if (Array.isArray(tool_groups)) {
      // Filter to only valid group IDs
      const validatedToolGroups = tool_groups.filter((g: string) => VALID_TOOL_GROUPS.includes(g));
      updates.tool_groups = validatedToolGroups.length > 0 ? validatedToolGroups : null;
    } else {
      return NextResponse.json({ error: 'tool_groups must be an array or null' }, { status: 400 });
    }
  }

  if (Object.keys(updates).length === 0) {
    return NextResponse.json({ error: 'No updates provided' }, { status: 400 });
  }

  // Get user by Clerk ID to get internal UUID
  const user = await getUserByClerkId(userId);
  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  const apiKey = await updateAPIKey(user.id, id, updates);

  if (!apiKey) {
    return NextResponse.json({ error: 'Failed to update API key' }, { status: 500 });
  }

  return NextResponse.json({
    id: apiKey.id,
    name: apiKey.name,
    tool_groups: apiKey.tool_groups,
    updated_at: apiKey.updated_at
  });
}

// DELETE - Delete an API key
export async function DELETE(req: NextRequest) {
  const { userId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const keyId = searchParams.get('id');

  if (!keyId) {
    return NextResponse.json({ error: 'Key ID is required' }, { status: 400 });
  }

  // Get user by Clerk ID to get internal UUID
  const user = await getUserByClerkId(userId);
  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  // Use helper function with internal user.id
  const success = await deleteAPIKey(user.id, keyId);

  if (!success) {
    return NextResponse.json({ error: 'Failed to delete API key' }, { status: 500 });
  }

  return NextResponse.json({ success: true });
}
