import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { supabase } from '@/lib/supabase';
import crypto from 'crypto';

// GET - List all API keys for the user
export async function GET(req: NextRequest) {
  const { userId } = auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { data, error } = await supabase
    .from('api_keys')
    .select('id, name, created_at, last_used_at')
    .eq('clerk_user_id', userId);

  if (error) {
    return NextResponse.json({ error: 'Failed to fetch API keys' }, { status: 500 });
  }

  return NextResponse.json({ keys: data });
}

// POST - Create a new API key
export async function POST(req: NextRequest) {
  const { userId } = auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { name } = await req.json();

  if (!name) {
    return NextResponse.json({ error: 'Name is required' }, { status: 400 });
  }

  // Generate a random API key
  const key = `sk_${crypto.randomBytes(32).toString('hex')}`;
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');

  const { data, error } = await supabase
    .from('api_keys')
    .insert([
      {
        clerk_user_id: userId,
        name,
        key_hash: keyHash,
      },
    ])
    .select()
    .single();

  if (error) {
    return NextResponse.json({ error: 'Failed to create API key' }, { status: 500 });
  }

  // Return the actual key only once (it won't be stored)
  return NextResponse.json({ key, id: data.id, name: data.name });
}

// DELETE - Delete an API key
export async function DELETE(req: NextRequest) {
  const { userId } = auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { searchParams } = new URL(req.url);
  const keyId = searchParams.get('id');

  if (!keyId) {
    return NextResponse.json({ error: 'Key ID is required' }, { status: 400 });
  }

  const { error } = await supabase
    .from('api_keys')
    .delete()
    .eq('id', keyId)
    .eq('clerk_user_id', userId);

  if (error) {
    return NextResponse.json({ error: 'Failed to delete API key' }, { status: 500 });
  }

  return NextResponse.json({ success: true });
}
