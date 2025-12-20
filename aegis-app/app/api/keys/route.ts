import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getUserByClerkId, getAPIKeys, createAPIKey, deleteAPIKey } from '@/lib/supabase';
import crypto from 'crypto';

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

  const { name } = await req.json();

  if (!name) {
    return NextResponse.json({ error: 'Name is required' }, { status: 400 });
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
  const apiKey = await createAPIKey(user.id, name, keyHash, keyPrefix);

  if (!apiKey) {
    return NextResponse.json({ error: 'Failed to create API key' }, { status: 500 });
  }

  // Return the actual key only once (it won't be stored)
  return NextResponse.json({ key, id: apiKey.id, name: apiKey.name });
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
