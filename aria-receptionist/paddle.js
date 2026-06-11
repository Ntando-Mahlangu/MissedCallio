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

const PRICE_IDS = {
  starter: process.env.PADDLE_STARTER_PRICE_ID || 'pro_01kt2ngxvvcc6w9q587b5z712r',
  growth:  process.env.PADDLE_GROWTH_PRICE_ID  || 'pro_01kt2nhn9wxy36bnb5rw484zgh',
  pro:     process.env.PADDLE_PRO_PRICE_ID     || 'pro_01kt2nk0e43xzah6j4rnt7mwdq',
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
    const res = await fetch(`${PADDLE_API}/transactions`, {
      method: 'POST',
      headers: {
        Authorization:  `Bearer ${process.env.PADDLE_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        items: [{
          price_id: priceId,
          quantity: 1
        }],
        customer: {
          email: business.email,
          name:  business.name
        },
        custom_data: {
          business_id:   business.id,
          business_name: business.business_name,
          plan:          business.plan
        },
        // 7-day trial before first charge
        billing_details: {
          enable_checkout: true
        },
        collection_mode: 'automatic',
        // Trial period — Paddle charges after 7 days
        discount_id: null,
      })
    });

    const data = await res.json();

    if (!res.ok) {
      console.error('Paddle checkout error:', JSON.stringify(data));
      return null;
    }

    console.log(`💳 Paddle checkout created for ${business.business_name}`);
    return data.data?.url || null;

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
export async function handlePaddleWebhook(req, res, supabase) {
  const signature = req.headers['paddle-signature'];

  // Verify webhook is genuinely from Paddle
  if (!verifyPaddleSignature(req.body, signature)) {
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
          await supabase.from('businesses').update({
            status:              'active',
            paddle_subscription_id: data.id,
            paddle_customer_id:     data.customer_id,
          }).eq('id', businessId);

          console.log(`✅ Subscription activated for business: ${businessId}`);
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
            status: 'cancelled',
            cancelled_at: new Date().toISOString()
          }).eq('id', businessId);

          console.log(`❌ Subscription cancelled for business: ${businessId}`);
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
// =============================================================
function verifyPaddleSignature(body, signature) {
  if (!signature || !process.env.PADDLE_WEBHOOK_SECRET) return false;

  try {
    // Paddle sends: ts=timestamp;h1=hash
    const parts = signature.split(';');
    const ts    = parts.find(p => p.startsWith('ts='))?.split('=')[1];
    const h1    = parts.find(p => p.startsWith('h1='))?.split('=')[1];

    if (!ts || !h1) return false;

    const payload  = `${ts}:${JSON.stringify(body)}`;
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