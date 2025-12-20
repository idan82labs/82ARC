import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@clerk/nextjs/server';
import { getUserByClerkId, getUserTier } from '@/lib/supabase';
import { createCheckoutSession } from '@/lib/stripe';

// GET - Get user's credit balance and tier
export async function GET(req: NextRequest) {
  const { userId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const user = await getUserByClerkId(userId);

  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  // Credits are now in user.credits.balance (separate table)
  return NextResponse.json({
    credits: user.credits.balance,
    tier: user.credits.tier,
    monthly_refill: user.credits.monthly_refill,
  });
}

// POST - Create a Stripe checkout session for purchasing credits
export async function POST(req: NextRequest) {
  const { userId } = await auth();

  if (!userId) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  const { packageKey } = await req.json();

  if (!packageKey || !['small', 'medium', 'large'].includes(packageKey)) {
    return NextResponse.json({ error: 'Invalid package' }, { status: 400 });
  }

  const user = await getUserByClerkId(userId);

  if (!user) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 });
  }

  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
  const successUrl = `${baseUrl}/dashboard/billing?success=true`;
  const cancelUrl = `${baseUrl}/dashboard/billing?canceled=true`;

  const session = await createCheckoutSession(
    user.id,
    packageKey,
    successUrl,
    cancelUrl
  );

  return NextResponse.json({ url: session.url });
}
