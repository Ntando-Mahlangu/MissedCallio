// =============================================================
//  MissedCall.io — Paddle Billing Integration
//  Add this to server.js once you have your Paddle keys
//
//  Required Railway variables:
//  PADDLE_API_KEY=your-paddle-api-key
//  PADDLE_WEBHOOK_SECRET=your-paddle-webhook-secret
//  PADDLE_STARTER_PRICE_ID=pri_xxxxxxxx
//  PADDLE_GROWTH_PRICE_ID=pri_xxxxxxxx
//  PADDLE_PRO_PRICE_ID=pri_xxxxxxxx
// =============================================================

import crypto from 'crypto';

const PADDLE_API = 'https://api.paddle.com';

// Price IDs must be set in Railway env vars (prefix: pri_)
// Leave the fallbacks empty — checkout will warn rather than silently use wrong IDs
const PRICE_IDS = {
  starter: process.env.PADDLE_STARTER_PRICE_ID || '',
  growth:  process.env.PADDLE_GROWTH_PRICE_ID  || '',
  pro:     process.env.PADDLE_PRO_PRICE_ID     || '',
};

// =============================================================
//  CREATE PADDLE CHECKOUT
//  Call this after a business signs up to start their trial
//  Returns a checkout URL to redirect the client to
// =============================================================
export async function createPaddleCheckout(business) {
  const priceId = PRICE_IDS[business.plan] || PRICE_IDS.growth;

  if (!priceId) {
    console.warn('No Paddle price ID for plan:', business.plan);
    return null;
  }

  try {
    // Paddle Billing v2: create a transaction via API and return the hosted checkout URL
    const paddleEnv = process.env.PADDLE_ENV === 'sandbox' ? 'sandbox' : 'production';
    const apiBase   = paddleEnv === 'sandbox'
      ? 'https://sandbox-api.paddle.com'
      : 'https://api.paddle.com';

    const response = await fetch(`${apiBase}/transactions`, {
      method: 'POST',
      headers: {
        Authorization:  `Bearer ${process.env.PADDLE_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        items: [{ price_id: priceId, quantity: 1 }],
        customer: { email: business.email },
        custom_data: {
          business_id:   business.id,
          business_name: business.business_name,
          plan:          business.plan,
        },
        checkout: { url: `${process.env.SERVER_URL || 'https://missedcallio.online'}/dashboard` },
      }),
    });

    const txData = await response.json();
    if (!response.ok) {
      console.error('Paddle transaction error:', JSON.stringify(txData));
      return null;
    }

    const checkoutUrl = txData.data?.checkout?.url || null;
    if (!checkoutUrl) {
      console.error('Paddle did not return a checkout URL:', JSON.stringify(txData));
      return null;
    }

    console.log(`Paddle checkout URL created for ${business.business_name}`);
    return checkoutUrl;

  } catch (err) {
    console.error('Paddle checkout failed:', err.message);
    return null;
  }
}

// =============================================================
//  PADDLE WEBHOOK HANDLER
//  Add this route to server.js:
//  app.post('/paddle/webhook', handlePaddleWebhook);
//
//  In Paddle dashboard → Webhooks → add:
//  URL: https://missedcallio.online/paddle/webhook
//  Events: subscription.activated, subscription.canceled,
//           subscription.past_due, transaction.completed
// =============================================================
export async function handlePaddleWebhook(req, res, supabase, rawBody) {
  const signature = req.headers['paddle-signature'];

  // Verify webhook is genuinely from Paddle using raw body bytes
  if (!verifyPaddleSignature(rawBody, signature)) {
    console.warn('Invalid Paddle webhook signature');
    return res.status(401).json({ error: 'Invalid signature' });
  }

  const { event_type, data } = req.body;
  console.log(`Paddle webhook: ${event_type}`);

  try {
    switch (event_type) {

      // Trial ended — subscription is now active and billing started
      case 'subscription.activated': {
        const businessId = data.custom_data?.business_id;
        if (businessId) {
          const planFromPrice = resolvePlanFromItems(data.items);
          await supabase.from('businesses').update({
            status:                 'active',
            paddle_subscription_id: data.id,
            paddle_customer_id:     data.customer_id,
            ...(planFromPrice && { plan: planFromPrice }),
          }).eq('id', businessId);
          console.log(`Subscription activated for business: ${businessId}`);
        }
        break;
      }

      // Subscription changed (plan upgrade/downgrade)
      case 'subscription.updated': {
        const businessId = data.custom_data?.business_id;
        if (businessId) {
          const planFromPrice = resolvePlanFromItems(data.items);
          await supabase.from('businesses').update({
            paddle_subscription_id: data.id,
            ...(planFromPrice && { plan: planFromPrice }),
            ...(data.status === 'active' && { status: 'active' }),
          }).eq('id', businessId);
          console.log(`Subscription updated for business: ${businessId}`);
        }
        break;
      }

      // Payment succeeded
      case 'transaction.completed': {
        const businessId = data.custom_data?.business_id;
        if (businessId) {
          await supabase.from('businesses').update({
            status: 'active',
            last_payment_at: new Date().toISOString()
          }).eq('id', businessId);

          console.log(`💰 Payment received for business: ${businessId}`);
        }
        break;
      }

      // Payment failed — give grace period
      case 'subscription.past_due': {
        const businessId = data.custom_data?.business_id;
        if (businessId) {
          await supabase.from('businesses').update({
            status: 'past_due'
          }).eq('id', businessId);

          // Notify business owner their payment failed
          const { data: business } = await supabase
            .from('businesses')
            .select('mobile_number, business_name')
            .eq('id', businessId)
            .single();

          if (business?.mobile_number) {
            await sendSMS(
              business.mobile_number,
              `Hi! Your MissedCall.io payment for ${business.business_name} failed. Please update your payment details at missedcallio.online to keep Aria answering your calls.`
            );
          }

          console.log(`⚠️ Payment past due for business: ${businessId}`);
        }
        break;
      }

      // Subscription cancelled
      case 'subscription.canceled': {
        const businessId = data.custom_data?.business_id;
        if (businessId) {
          await supabase.from('businesses').update({
            status:       'cancelled',
            cancelled_at: new Date().toISOString(),
            paddle_subscription_id: data.id,
          }).eq('id', businessId);
          console.log(`Subscription cancelled for business: ${businessId}`);
        }
        break;
      }

      default:
        console.log(`Unhandled Paddle event: ${event_type}`);
    }
  } catch (err) {
    console.error('Paddle webhook handler error:', err.message);
  }

  // Always return 200 to Paddle
  return res.json({ received: true });
}

// =============================================================
//  VERIFY PADDLE WEBHOOK SIGNATURE
//  rawBody must be the raw Buffer captured before JSON parsing
// =============================================================
function verifyPaddleSignature(rawBody, signature) {
  if (!signature || !process.env.PADDLE_WEBHOOK_SECRET) return false;

  try {
    // Paddle sends: ts=timestamp;h1=hash
    const parts = signature.split(';');
    const ts    = parts.find(p => p.startsWith('ts='))?.split('=')[1];
    const h1    = parts.find(p => p.startsWith('h1='))?.split('=')[1];

    if (!ts || !h1) return false;

    // Must use the raw body bytes, not re-serialised JSON
    const rawStr   = rawBody ? rawBody.toString('utf8') : '';
    const payload  = `${ts}:${rawStr}`;
    const expected = crypto
      .createHmac('sha256', process.env.PADDLE_WEBHOOK_SECRET)
      .update(payload)
      .digest('hex');

    return crypto.timingSafeEqual(
      Buffer.from(h1, 'hex'),
      Buffer.from(expected, 'hex')
    );
  } catch (err) {
    console.error('Signature verification error:', err.message);
    return false;
  }
}

// =============================================================
//  RESOLVE PLAN FROM SUBSCRIPTION ITEMS
// =============================================================
function resolvePlanFromItems(items) {
  if (!items || !Array.isArray(items)) return null;
  for (const item of items) {
    const priceId = item.price?.id || item.price_id;
    if (!priceId) continue;
    for (const [plan, pid] of Object.entries(PRICE_IDS)) {
      if (pid === priceId) return plan;
    }
  }
  return null;
}

// =============================================================
//  CANCEL PADDLE SUBSCRIPTION
//  Call this if a business wants to cancel from their dashboard
// =============================================================
export async function cancelPaddleSubscription(subscriptionId) {
  try {
    const res = await fetch(`${PADDLE_API}/subscriptions/${subscriptionId}/cancel`, {
      method: 'POST',
      headers: {
        Authorization:  `Bearer ${process.env.PADDLE_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ effective_from: 'next_billing_period' })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(JSON.stringify(data));

    console.log(`Subscription ${subscriptionId} cancelled`);
    return { success: true };

  } catch (err) {
    console.error('Cancel subscription error:', err.message);
    return { success: false, error: err.message };
  }
}

// Helper — reuse SMS function from server.js
async function sendSMS(to, body) {
  if (!process.env.TWILIO_ACCOUNT_SID) return;

  const creds = Buffer.from(
    `${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`
  ).toString('base64');

  await fetch(
    `https://api.twilio.com/2010-04-01/Accounts/${process.env.TWILIO_ACCOUNT_SID}/Messages.json`,
    {
      method:  'POST',
      headers: {
        Authorization:  `Basic ${creds}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        To:   to,
        From: process.env.TWILIO_FROM_NUMBER,
        Body: body
      })
    }
  );
}