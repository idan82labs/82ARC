import { headers } from 'next/headers';
import { constructWebhookEvent } from '@/lib/stripe';
import { updateUserCredits } from '@/lib/supabase';

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
      const { userId, credits, bonus } = session.metadata || {};

      if (userId && credits) {
        const totalCredits = parseInt(credits) + (parseInt(bonus || '0'));
        await updateUserCredits(userId, totalCredits);
        console.log(`Added ${totalCredits} credits to user ${userId}`);
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
