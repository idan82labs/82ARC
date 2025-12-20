import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getUserByClerkId } from '@/lib/supabase';

// GET - Get user's credit balance and tier
export async function GET(req: NextRequest) {
  const { userId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  // Get user by Clerk ID to get internal UUID and credits
  const user = await getUserByClerkId(userId);
  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  return NextResponse.json({
    balance: user.credits.balance,
    tier: user.credits.tier,
    monthly_refill: user.credits.monthly_refill,
  });
}
