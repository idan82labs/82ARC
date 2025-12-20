import { headers } from 'next/headers';
import { constructWebhookEvent } from '@/lib/stripe';
import { getUserByClerkId, addCredits, recordTransaction } from '@/lib/supabase';

export async function POST(req: Request) {
  const body = await req.text();
  const signature = headers().get('stripe-signature') as string;

  let event;

  try {
    event = constructWebhookEvent(body, signature);
  } catch (err) {
    console.error('Webhook signature verification failed:', err);
    return new Response('Webhook Error', { status: 400 });
  }

  // Handle the event
  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      // userId in metadata is the Clerk ID, not the internal UUID
      const { userId: clerkId, credits, bonus } = session.metadata || {};

      if (clerkId && credits) {
        // Look up user by Clerk ID to get internal UUID
        const user = await getUserByClerkId(clerkId);
        if (!user) {
          console.error(`User not found for Clerk ID: ${clerkId}`);
          break;
        }

        const totalCredits = parseInt(credits) + (parseInt(bonus || '0'));
        const amountCents = session.amount_total || 0;

        // Add credits using internal user ID
        await addCredits(user.id, totalCredits);

        // Record the transaction for audit trail
        await recordTransaction(
          user.id,
          'purchase',
          totalCredits,
          amountCents,
          session.payment_intent as string
        );

        console.log(`Added ${totalCredits} credits to user ${user.id} (Clerk: ${clerkId})`);
      }
      break;
    }

    case 'payment_intent.succeeded': {
      console.log('PaymentIntent was successful!');
      break;
    }

    case 'payment_intent.payment_failed': {
      console.log('PaymentIntent failed.');
      break;
    }

    default:
      console.log(`Unhandled event type ${event.type}`);
  }

  return new Response(JSON.stringify({ received: true }), { status: 200 });
}
