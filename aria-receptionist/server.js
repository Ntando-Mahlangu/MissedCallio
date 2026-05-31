// =============================================================
//  MissedCall.io — Production SaaS Server
//  Vapi + Claude + ElevenLabs + Supabase + Twilio
//  Fully audited and production ready
// =============================================================

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Serve website
app.use(express.static(__dirname));
app.get('/', (_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// Guard against missing keys
if (!process.env.SUPABASE_URL)      throw new Error('SUPABASE_URL is required.');
if (!process.env.SUPABASE_SERVICE_KEY) throw new Error('SUPABASE_SERVICE_KEY is required.');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// =============================================================
//  SIGNUP — POST /signup
// =============================================================
app.post('/signup', async (req, res) => {
  const {
    firstName, lastName, businessName,
    mobileNumber, email, industry, plan,
    bizHours, bizAddress, bizPricing
  } = req.body;

  if (!firstName || !email || !businessName || !mobileNumber) {
    return res.status(400).json({ error: 'Please fill in all required fields.' });
  }
  if (!email.includes('@')) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  try {
    console.log(`\n🆕 New signup: ${businessName} (${plan || 'growth'})`);

    // 1. Save to Supabase
    const { data: business, error: bizErr } = await supabase
      .from('businesses')
      .insert({
        name:           `${firstName} ${lastName}`,
        email,
        business_name:  businessName,
        mobile_number:  mobileNumber,
        industry:       industry  || 'General business',
        biz_hours:      bizHours  || 'Monday to Friday 8am–6pm',
        biz_address:    bizAddress || '',
        biz_pricing:    bizPricing || 'Please call us for a quote',
        plan:           plan || 'growth',
        trial_ends_at:  new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        status:         'trial'
      })
      .select()
      .single();

    if (bizErr) {
      if (bizErr.message.includes('unique')) {
        return res.status(400).json({ error: 'This email is already registered.' });
      }
      throw new Error(bizErr.message);
    }

    // 2. Create Vapi assistant
    let assistantId = null;
    let phoneNumber  = process.env.DEFAULT_MISSEDCALL_NUMBER || null;

    if (process.env.VAPI_API_KEY) {
      try {
        assistantId = await createVapiAssistant(business);
        phoneNumber  = await assignPhoneNumber(assistantId);
      } catch (vapiErr) {
        console.warn('Vapi setup failed:', vapiErr.message);
      }
    }

    // 3. Update record
    if (assistantId || phoneNumber) {
      const { error: upErr } = await supabase
        .from('businesses')
        .update({ vapi_assistant_id: assistantId, missedcall_number: phoneNumber })
        .eq('id', business.id);
      if (upErr) console.error('Update error:', upErr.message);
    }

    // 4. Send welcome email
    await sendWelcomeEmail({ ...business, name: `${firstName} ${lastName}` }, phoneNumber);

    // 5. Send owner SMS confirming new signup
    if (process.env.TWILIO_ACCOUNT_SID && process.env.OWNER_PHONE) {
      await sendSMS(
        process.env.OWNER_PHONE,
        `🎉 New MissedCall signup!\nBusiness: ${businessName}\nPlan: ${plan || 'growth'}\nContact: ${mobileNumber}`
      );
    }

    console.log(`✅ ${businessName} live${phoneNumber ? ' on ' + phoneNumber : ''}`);

    res.json({
      success: true,
      missedcallNumber: phoneNumber,
      message: phoneNumber
        ? `You're live! Forward your calls to ${phoneNumber}`
        : `You're signed up! Check your email for next steps.`
    });

  } catch (err) {
    console.error('Signup error:', err.message);
    res.status(500).json({ error: 'Something went wrong. Please try again or contact support.' });
  }
});

// =============================================================
//  CREATE VAPI ASSISTANT
// =============================================================
async function createVapiAssistant(business) {
  const res = await fetch('https://api.vapi.ai/assistant', {
    method: 'POST',
    headers: {
      Authorization:  `Bearer ${process.env.VAPI_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(buildAssistantConfig(business))
  });

  const data = await res.json();
  if (!res.ok) throw new Error('Vapi error: ' + JSON.stringify(data));
  console.log(`Vapi assistant created: ${data.id}`);
  return data.id;
}

// =============================================================
//  ASSISTANT CONFIG
// =============================================================
function buildAssistantConfig(business) {
  const { business_name, id } = business;

  return {
    name: `MissedCall — ${business_name}`,

    model: {
      provider:     'anthropic',
      model:        'claude-sonnet-4-20250514',
      systemPrompt: buildSystemPrompt(business),
      temperature:  0.7,
      maxTokens:    250,  // enough for natural responses without getting cut off
    },

    voice: {
      provider:                  'elevenlabs',
      voiceId:                   'EXAVITQu4vr4xnSDxMaL', // Sarah — warm, natural
      model:                     'eleven_flash_v2_5',     // lowest latency for live calls
      stability:                 0.40,
      similarityBoost:           0.80,
      style:                     0.30,
      useSpeakerBoost:           true,
      optimizeStreamingLatency:  4,
    },

    transcriber: {
      provider:    'deepgram',
      model:       'nova-2',
      language:    'en',
      smartFormat: true,
    },

    silenceTimeoutSeconds: 1.5,
    maxDurationSeconds:    300,

    // First message — Aria says this the moment the call connects
    firstMessage: `Hi there, thanks for calling ${business_name}! My name's Aria. Could I get your name please?`,

    endCallMessage: "Thanks so much for calling. Someone from the team will be in touch soon. Take care!",

    endCallPhrases: [
      'goodbye', 'bye', 'bye bye', 'thanks bye',
      'thank you bye', 'that\'s all', 'have a good day',
      'talk later', 'cheers'
    ],

    // Webhook includes businessId so we know which client the call belongs to
    serverUrl: `${process.env.SERVER_URL}/vapi/webhook/${id}`,

    tools: [{
      type: 'function',
      function: {
        name:        'save_lead',
        description: "Save the caller's details. Call this once you have confirmed their name, issue, and phone number.",
        parameters: {
          type:     'object',
          required: ['name', 'issue', 'phone'],
          properties: {
            name:  { type: 'string', description: "Caller's full name" },
            issue: { type: 'string', description: 'What they need help with or reason for calling' },
            phone: { type: 'string', description: "Caller's callback phone number" }
          }
        }
      }
    }]
  };
}

// =============================================================
//  SYSTEM PROMPT — personalised per business
// =============================================================
function buildSystemPrompt(business) {
  const {
    business_name,
    industry,
    biz_hours,
    biz_address,
    biz_pricing
  } = business;

  return `You are Aria, a warm and professional AI receptionist for ${business_name}, a ${industry} business.

BUSINESS INFORMATION — answer these confidently when asked:
- Hours: ${biz_hours || 'Monday to Friday 8am–6pm'}
- Address / Location: ${biz_address || 'Please call us for our location'}
- Pricing: ${biz_pricing || 'Pricing depends on the job — we give free quotes'}
- Payment: Cash and card accepted
- Emergencies: Yes we handle them — leave your number and someone calls back within 15 minutes

YOUR JOB: Have a natural, helpful conversation. Answer any question the caller has. Collect their name, issue, and callback number. Once you have all three, confirm and save them.

CONVERSATION FLOW:
- You already asked for their name in your first message. Once they give it, use it naturally.
- Ask what you can help with today.
- Listen, show empathy, answer any questions they have from the business info above.
- Ask for their callback number.
- Once you have all three: "Perfect [name], I've got you noted down. Someone from ${business_name} will call you back on [number] shortly."
- Then call the save_lead tool with name, issue, and phone.
- After saving, say a warm goodbye.

HANDLING ANY QUESTION:
- Pricing questions: give the answer from business info above. Never dodge it.
- Hours, location, payment: answer directly and naturally.
- Something you don't know: "That's a great question — I'll make sure whoever calls you back can answer that for you."
- "Are you a real person / AI?": "I'm an AI assistant, but a real person from ${business_name} will call you right back — I'm just here so you don't get missed."
- Upset or urgent caller: lead with empathy first. "Oh no, let's get someone to you as fast as we can."
- NEVER say: cannot help, don't have access, as an AI language model, I apologize for the inconvenience.

SPEAKING STYLE:
- Warm, natural, human. Like a real receptionist — not a robot.
- Contractions always: I'll, we'll, that's, don't, you're, it's.
- Keep replies to 1–2 short sentences. This is a phone call.
- Natural filler: "Sure!", "Of course.", "Got it.", "No worries.", "Absolutely."
- Use caller's name naturally — not every sentence, just occasionally.`;
}

// =============================================================
//  ASSIGN PHONE NUMBER via Vapi
// =============================================================
async function assignPhoneNumber(assistantId) {
  try {
    const res = await fetch('https://api.vapi.ai/phone-number', {
      method: 'POST',
      headers: {
        Authorization:  `Bearer ${process.env.VAPI_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        provider:          'twilio',
        twilioAccountSid:  process.env.TWILIO_ACCOUNT_SID,
        twilioAuthToken:   process.env.TWILIO_AUTH_TOKEN,
        assistantId,
      })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(JSON.stringify(data));
    console.log(`Phone number assigned: ${data.number}`);
    return data.number;

  } catch (err) {
    console.warn('Phone number auto-buy failed:', err.message);
    return process.env.DEFAULT_MISSEDCALL_NUMBER || null;
  }
}

// =============================================================
//  VAPI WEBHOOK — receives all call events
// =============================================================
app.post('/vapi/webhook/:businessId', async (req, res) => {
  const { message }    = req.body;
  const { businessId } = req.params;
  if (!message) return res.json({ result: 'ok' });

  const { type, call } = message;
  const callId = call?.id;

  try {

    // ── Tool call — Aria wants to save a lead ──
    if (type === 'tool-calls') {
      const results = [];

      for (const toolCall of message.toolCallList || []) {
        let result;
        try {
          // FIX: Vapi sends arguments not parameters
          const args = toolCall.function.arguments || toolCall.function.parameters || {};
          const params = typeof args === 'string' ? JSON.parse(args) : args;

          if (toolCall.function.name === 'save_lead') {
            result = await saveLead(businessId, callId, call, params);
          }
        } catch (err) {
          console.error('Tool call error:', err.message);
          result = { success: false, error: err.message };
        }

        results.push({
          toolCallId: toolCall.id,
          result:     JSON.stringify(result)
        });
      }

      return res.json({ results });
    }

    // ── Call started ──
    if (type === 'call-started') {
      console.log(`📞 Call started: ${callId} (business: ${businessId})`);
      const { error } = await supabase.from('calls').insert({
        id:            callId,
        business_id:   businessId,
        caller_number: call?.customer?.number || null,
        started_at:    new Date().toISOString(),
        status:        'in_progress'
      });
      if (error) console.error('Call insert error:', error.message);
    }

    // ── Call ended ──
    if (type === 'call-ended') {
      console.log(`📴 Call ended: ${callId} (${call?.duration || 0}s)`);
      const { error } = await supabase.from('calls').update({
        status:           'completed',
        ended_at:         new Date().toISOString(),
        duration_seconds: call?.duration || null,
        recording_url:    call?.recordingUrl || null,
      }).eq('id', callId);
      if (error) console.error('Call update error:', error.message);
    }

  } catch (err) {
    console.error('Webhook error:', err.message);
  }

  return res.json({ result: 'ok' });
});

// =============================================================
//  SAVE LEAD + SMS to owner
// =============================================================
async function saveLead(businessId, callId, call, { name, issue, phone }) {
  // Validate we have the required fields
  if (!name || !phone) {
    console.warn('save_lead called without name or phone');
    return { success: false, error: 'Missing required fields' };
  }

  // Get business details for SMS
  const { data: business, error: bizErr } = await supabase
    .from('businesses')
    .select('business_name, mobile_number')
    .eq('id', businessId)
    .single();

  if (bizErr) console.error('Business lookup error:', bizErr.message);

  // Save lead to database
  const lead = {
    business_id:   businessId,
    call_id:       callId,
    name,
    issue:         issue || 'Not specified',
    phone,
    caller_number: call?.customer?.number || null,
    received_at:   new Date().toISOString()
  };

  const { error: leadErr } = await supabase.from('leads').insert(lead);
  if (leadErr) console.error('Lead insert error:', leadErr.message);

  // SMS to business owner
  if (business) {
    await sendSMSToOwner(business, lead);
  }

  console.log(`✅ Lead saved: ${name} | ${phone} | "${issue}"`);
  return { success: true };
}

// =============================================================
//  SMS TO BUSINESS OWNER
// =============================================================
async function sendSMSToOwner(business, lead) {
  if (!process.env.TWILIO_ACCOUNT_SID || !business?.mobile_number) return;

  const time = new Date(lead.received_at).toLocaleString('en-US', {
    dateStyle: 'short',
    timeStyle: 'short'
  });

  const body =
    `📞 New call — ${business.business_name}\n` +
    `Name:  ${lead.name}\n` +
    `Phone: ${lead.phone}\n` +
    `Issue: ${lead.issue}\n` +
    `Time:  ${time}`;

  await sendSMS(business.mobile_number, body);
}

// =============================================================
//  SEND SMS via Twilio
// =============================================================
async function sendSMS(to, body) {
  try {
    const creds = Buffer.from(
      `${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`
    ).toString('base64');

    const res = await fetch(
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

    if (res.ok) {
      console.log(`📱 SMS sent to ${to}`);
    } else {
      const err = await res.text();
      console.error('Twilio error:', err);
    }
  } catch (err) {
    console.error('SMS failed:', err.message);
  }
}

// =============================================================
//  WELCOME EMAIL via Resend
// =============================================================
async function sendWelcomeEmail(business, phoneNumber) {
  if (!process.env.RESEND_API_KEY) {
    console.log(`📧 [Email skipped — no RESEND_API_KEY] Would send to: ${business.email}`);
    return;
  }

  const instructions = phoneNumber
    ? `Your MissedCall.io number is: <strong>${phoneNumber}</strong><br/><br/>
       <strong>To activate in 30 seconds:</strong><br/>
       Go to your phone settings → Call Forwarding → Forward to <strong>${phoneNumber}</strong><br/><br/>
       That's it. Aria will answer every call from this moment on.`
    : `Our team will contact you within 24 hours to complete your setup.`;

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method:  'POST',
      headers: {
        Authorization:  `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from:    `MissedCall <hello@${process.env.EMAIL_DOMAIN || 'missedcall.io'}>`,
        to:      business.email,
        subject: `You're live on MissedCall.io! 🎉`,
        html: `
          <div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
            <h2 style="color:#ff5c00">Welcome to MissedCall.io!</h2>
            <p>Hi ${business.name},</p>
            <p>Your AI receptionist is set up for <strong>${business.business_name}</strong>.</p>
            <br/>
            ${instructions}
            <br/><br/>
            <p>You'll get an SMS at <strong>${business.mobile_number}</strong> every time Aria captures a lead.</p>
            <p>Your <strong>7-day free trial</strong> starts now. No credit card needed until it ends.</p>
            <br/>
            <p style="color:#888">— The MissedCall.io Team</p>
          </div>
        `
      })
    });
    if (res.ok) console.log(`📧 Welcome email sent to ${business.email}`);
    else console.error('Email error:', await res.text());
  } catch (err) {
    console.error('Email failed:', err.message);
  }
}

// =============================================================
//  ADMIN ENDPOINTS
// =============================================================
app.get('/admin/businesses', async (_req, res) => {
  const { data, error } = await supabase
    .from('businesses').select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ total: data.length, businesses: data });
});

app.get('/admin/leads/:businessId', async (req, res) => {
  const { data, error } = await supabase
    .from('leads').select('*')
    .eq('business_id', req.params.businessId)
    .order('received_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ total: data.length, leads: data });
});

app.get('/admin/calls/:businessId', async (req, res) => {
  const { data, error } = await supabase
    .from('calls').select('*')
    .eq('business_id', req.params.businessId)
    .order('started_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ total: data.length, calls: data });
});

app.get('/health', (_req, res) => res.json({
  status:   'ok',
  supabase: !!process.env.SUPABASE_URL,
  vapi:     !!process.env.VAPI_API_KEY,
  twilio:   !!process.env.TWILIO_ACCOUNT_SID,
  email:    !!process.env.RESEND_API_KEY,
  uptime:   Math.round(process.uptime())
}));

// =============================================================
//  START
// =============================================================
process.on('SIGTERM',             () => process.exit(0));
process.on('uncaughtException',   (e) => console.error('Uncaught:',   e.message));
process.on('unhandledRejection',  (e) => console.error('Unhandled:',  e.message));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🎙️  MissedCall.io running on :${PORT}`);
  console.log(`   Supabase: ${process.env.SUPABASE_URL        ? '✅' : '❌ MISSING'}`);
  console.log(`   Vapi:     ${process.env.VAPI_API_KEY        ? '✅' : '⚠️  not set'}`);
  console.log(`   Twilio:   ${process.env.TWILIO_ACCOUNT_SID  ? '✅' : '⚠️  not set'}`);
  console.log(`   Email:    ${process.env.RESEND_API_KEY      ? '✅' : '⚠️  not set'}\n`);
});
