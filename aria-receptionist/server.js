// =============================================================
//  MissedCallio — Production SaaS Server
//  Vapi + Claude + ElevenLabs + Supabase + Twilio + Paddle
// =============================================================

import * as Sentry from '@sentry/node';
import express    from 'express';
import helmet     from 'helmet';
import rateLimit  from 'express-rate-limit';
import { createClient } from '@supabase/supabase-js';
import crypto     from 'crypto';
import dotenv     from 'dotenv';
import path       from 'path';
import { fileURLToPath } from 'url';
import { createPaddleCheckout, handlePaddleWebhook, cancelPaddleSubscription } from './paddle.js';
dotenv.config();

if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn:              process.env.SENTRY_DSN,
    tracesSampleRate: 0.1,
  });
  console.log('[sentry] error monitoring active');
}

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// =============================================================
//  STARTUP GUARDS
// =============================================================
if (!process.env.SUPABASE_URL)         throw new Error('SUPABASE_URL is required.');
if (!process.env.SUPABASE_SERVICE_KEY) throw new Error('SUPABASE_SERVICE_KEY is required.');
if (!process.env.TOKEN_SECRET)         throw new Error('TOKEN_SECRET is required — generate with: openssl rand -hex 32');
if (!process.env.ADMIN_KEY)            throw new Error('ADMIN_KEY is required.');

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// =============================================================
//  EXPRESS SETUP
// =============================================================
const app = express();

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:  ["'self'"],
      scriptSrc:   ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      styleSrc:    ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://fonts.gstatic.com'],
      fontSrc:     ["'self'", 'https://fonts.gstatic.com'],
      connectSrc:  ["'self'"],
      frameSrc:    ["'none'"],
      objectSrc:   ["'none'"],
    }
  },
  frameguard:     { action: 'deny' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
}));

app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf; }
}));
app.use(express.urlencoded({ extended: true }));

// CORS — support comma-separated ALLOWED_ORIGINS; never wildcard on credentialled routes
const _corsEnvList = process.env.ALLOWED_ORIGINS || process.env.ALLOWED_ORIGIN || process.env.SERVER_URL;
if (!_corsEnvList) {
  console.warn('[cors] No ALLOWED_ORIGINS set — falling back to http://localhost:3000 (dev mode)');
}
app.use((req, res, next) => {
  const origin  = req.headers.origin;
  const rawList = _corsEnvList || 'http://localhost:3000';
  const allowed = rawList.split(',').map(s => s.trim());
  if (!origin || allowed.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin || allowed[0]);
  }
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Key');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// =============================================================
//  STATIC FILES — explicit allowlist only (never serve server.js / .env)
// =============================================================
const SAFE_FILES = {
  '/':           'index.html',
  '/dashboard':  'dashboard.html',
};
for (const [route, file] of Object.entries(SAFE_FILES)) {
  app.get(route, (_req, res) => res.sendFile(path.join(__dirname, file)));
}
app.get('/terms',           (_req, res) => res.sendFile('terms.html',           { root: __dirname }));
app.get('/privacy',         (_req, res) => res.sendFile('privacy.html',         { root: __dirname }));
app.get('/refund',          (_req, res) => res.sendFile('refund.html',          { root: __dirname }));
app.get('/call-forwarding', (_req, res) => res.sendFile('call-forwarding.html', { root: __dirname }));

// =============================================================
//  RATE LIMITERS
// =============================================================
const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,  // 1 hour
  max:      5,
  message:  { error: 'Too many signup attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders:   false,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max:      10,
  message:  { error: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders:   false,
});

// =============================================================
//  PHONE NORMALISATION — converts common formats to E.164
// =============================================================
function normalizePhone(raw) {
  if (!raw) return raw;
  let s = raw.trim().replace(/[\s\-().]/g, '');
  if (/^\+\d{7,15}$/.test(s)) return s;
  if (s.startsWith('+')) return s;
  if (s.startsWith('00')) return '+' + s.slice(2);
  // Bare 10-digit US number starting with area code (2-9)
  if (/^\d{10}$/.test(s) && /^[2-9]/.test(s)) return '+1' + s;
  return s;
}

function countryCodeFromPhone(phone) {
  if (!phone) return 'US';
  const e = normalizePhone(phone);
  if (e.startsWith('+1'))   return 'US';
  if (e.startsWith('+44'))  return 'GB';
  if (e.startsWith('+27'))  return 'ZA';
  if (e.startsWith('+52'))  return 'MX';
  if (e.startsWith('+61'))  return 'AU';
  if (e.startsWith('+64'))  return 'NZ';
  if (e.startsWith('+353')) return 'IE';
  if (e.startsWith('+49'))  return 'DE';
  if (e.startsWith('+33'))  return 'FR';
  if (e.startsWith('+39'))  return 'IT';
  if (e.startsWith('+34'))  return 'ES';
  if (e.startsWith('+31'))  return 'NL';
  if (e.startsWith('+55'))  return 'BR';
  if (e.startsWith('+91'))  return 'IN';
  if (e.startsWith('+65'))  return 'SG';
  if (e.startsWith('+971')) return 'AE';
  return 'US';
}

// =============================================================
//  SIGNUP — POST /signup
// =============================================================
app.post('/signup', signupLimiter, async (req, res) => {
  const {
    firstName, lastName, businessName,
    mobileNumber, email, industry, plan,
    bizHours, bizAddress, bizPricing,
    departments, teamSize, officeType
  } = req.body;

  if (!firstName || !email || !businessName || !mobileNumber) {
    return res.status(400).json({ error: 'Please fill in all required fields.' });
  }
  if (!email.includes('@')) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  try {
    console.log(`[signup] ${businessName} (${plan || 'growth'})`);

    const { data: business, error: bizErr } = await supabase
      .from('businesses')
      .insert({
        name:          `${firstName} ${lastName}`,
        email:         email.toLowerCase().trim(),
        business_name: businessName,
        mobile_number: normalizePhone(mobileNumber),
        industry:      industry  || 'General business',
        biz_hours:     bizHours  || 'Monday to Friday 8am–6pm',
        biz_address:   bizAddress || '',
        biz_pricing:   bizPricing || 'Please call us for a quote',
        plan:          plan || 'growth',
        trial_ends_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
        status:        'trial',
        departments:   departments || null,
        team_size:     teamSize    || null,
        office_type:   officeType  || 'solo',
        referral_code: crypto.randomBytes(4).toString('hex'),
        referred_by_code: req.body.referralCode || null,
      })
      .select()
      .single();

    if (bizErr) {
      if (bizErr.message.includes('unique')) {
        return res.status(400).json({ error: 'This email is already registered.' });
      }
      throw new Error(bizErr.message);
    }

    let assistantId = null;
    let phoneNumber  = process.env.DEFAULT_MISSEDCALL_NUMBER || null;

    if (process.env.VAPI_API_KEY) {
      try {
        assistantId = await createVapiAssistant(business);
        phoneNumber  = await assignPhoneNumber(assistantId, business.mobile_number);
      } catch (vapiErr) {
        console.warn('[signup] Vapi setup failed:', vapiErr.message);
      }
    }

    if (assistantId || phoneNumber) {
      await supabase.from('businesses')
        .update({ vapi_assistant_id: assistantId, missedcall_number: phoneNumber })
        .eq('id', business.id);
    }

    await sendWelcomeEmail({ ...business, name: `${firstName} ${lastName}` }, phoneNumber);

    if (process.env.TWILIO_ACCOUNT_SID && process.env.OWNER_PHONE) {
      await sendSMS(
        process.env.OWNER_PHONE,
        `New MissedCallio signup!\nBusiness: ${businessName}\nPlan: ${plan || 'growth'}\nContact: ${normalizePhone(mobileNumber)}`
      );
    }

    // Create Paddle checkout if configured
    let checkoutUrl = null;
    if (process.env.PADDLE_API_KEY) {
      try {
        checkoutUrl = await createPaddleCheckout({ ...business, name: `${firstName} ${lastName}` });
      } catch (paddleErr) {
        console.warn('[signup] Paddle checkout failed:', paddleErr.message);
      }
    }

    console.log(`[signup] ${businessName} live${phoneNumber ? ' on ' + phoneNumber : ''}`);
    const dashboardUrl = process.env.SERVER_URL ? process.env.SERVER_URL + '/dashboard' : '/dashboard';
    res.json({
      success: true,
      missedcallNumber: phoneNumber,
      checkoutUrl,
      dashboardUrl,
      message: phoneNumber
        ? `You're live! Forward your calls to ${phoneNumber}`
        : `You're signed up! Check your email for next steps.`
    });

  } catch (err) {
    console.error('[signup] error:', err.message);
    res.status(500).json({ error: 'Something went wrong. Please try again or contact support.' });
  }
});

// =============================================================
//  CREATE VAPI ASSISTANT
// =============================================================
async function createVapiAssistant(business) {
  const r = await fetch('https://api.vapi.ai/assistant', {
    method:  'POST',
    headers: { Authorization: `Bearer ${process.env.VAPI_API_KEY}`, 'Content-Type': 'application/json' },
    body:    JSON.stringify(buildAssistantConfig(business))
  });
  const data = await r.json();
  if (!r.ok) throw new Error('Vapi error: ' + JSON.stringify(data));
  console.log(`[vapi] assistant created: ${data.id}`);
  return data.id;
}

// =============================================================
//  ASSISTANT CONFIG
// =============================================================
function buildAssistantConfig(business) {
  const { business_name, id, plan, ai_name } = business;
  const receptionist = ai_name || 'Aria';
  const canBook = plan === 'growth' || plan === 'pro';

  const tools = [{
    type: 'function',
    function: {
      name:        'save_lead',
      description: "Save the caller's details. Call this once you have their name, issue, and phone number.",
      parameters: {
        type:     'object',
        required: ['name', 'issue', 'phone'],
        properties: {
          name:  { type: 'string', description: "Caller's full name" },
          issue: { type: 'string', description: 'Reason for calling' },
          phone: { type: 'string', description: "Caller's callback number" }
        }
      }
    }
  }];

  if (canBook) {
    tools.push({
      type: 'function',
      function: {
        name:        'book_appointment',
        description: "Book an appointment. Use after confirming name, phone, service, and preferred date/time.",
        parameters: {
          type:     'object',
          required: ['name', 'phone', 'service', 'appointment_time'],
          properties: {
            name:             { type: 'string' },
            phone:            { type: 'string' },
            service:          { type: 'string', description: "Service or package" },
            appointment_time: { type: 'string', description: "ISO 8601, e.g. 2025-07-15T14:00:00" },
            timezone:         { type: 'string', description: "IANA timezone, e.g. America/New_York. Use the business timezone if known." },
            notes:            { type: 'string' }
          }
        }
      }
    });
  }

  if (plan === 'pro') {
    tools.push({
      type: 'function',
      function: {
        name: 'route_to_staff',
        description: "Look up a staff member the caller wants to reach.",
        parameters: {
          type: 'object',
          required: ['staff_name'],
          properties: {
            staff_name: { type: 'string', description: "Name or department the caller asked for" }
          }
        }
      }
    });
  }

  return {
    name:  `MissedCall — ${business_name}`,
    model: {
      provider:     'anthropic',
      model:        'claude-sonnet-4-5',
      systemPrompt: buildSystemPrompt(business),
      temperature:  0.7,
      maxTokens:    250,
    },
    voice: {
      provider:                 'elevenlabs',
      voiceId:                  'EXAVITQu4vr4xnSDxMaL', // Sarah
      model:                    'eleven_flash_v2_5',
      stability:                0.40,
      similarityBoost:          0.80,
      style:                    0.30,
      useSpeakerBoost:          true,
      optimizeStreamingLatency: 4,
    },
    transcriber: { provider: 'deepgram', model: 'nova-2', language: 'en', smartFormat: true },
    silenceTimeoutSeconds: 1.5,
    maxDurationSeconds:    300,
    firstMessage:    `Hi there, thanks for calling ${business_name}! My name's ${receptionist}. Could I get your name please?`,
    endCallMessage:  "Thanks so much for calling. Someone from the team will be in touch soon. Take care!",
    endCallPhrases:  ['goodbye','bye','bye bye','thanks bye','thank you bye',"that's all",'have a good day','talk later','cheers'],
    serverUrl:       `${process.env.SERVER_URL}/vapi/webhook/${id}`,
    serverUrlSecret: process.env.VAPI_WEBHOOK_SECRET || undefined,
    tools
  };
}

// =============================================================
//  SYSTEM PROMPT
// =============================================================
function buildSystemPrompt(business) {
  const { business_name, industry, biz_hours, biz_address, biz_pricing, plan, hold_message, departments, office_type, ai_name, after_hours_only } = business;
  const receptionist = ai_name || 'Aria';
  const canBook = plan === 'growth' || plan === 'pro';

  const deptList = departments
    ? departments.split(',').map(d => d.trim()).filter(Boolean)
    : [];
  const hasDepts = deptList.length > 1;
  const isOffice = office_type === 'small_office' || office_type === 'clinic' || office_type === 'agency';

  const deptRouting = hasDepts ? `

DEPARTMENT ROUTING:
- After getting the caller's name, ask: "Are you calling for ${deptList.slice(0,-1).join(', ')} or ${deptList.slice(-1)[0]}?"
- Note their department in the issue field when saving the lead, e.g. "Sales enquiry — needs quote for 50 units"
- If unsure which department: "No problem — I'll make sure the right person calls you back."` : '';

  const officeContext = isOffice ? `

OFFICE CONTEXT:
- This is a professional office environment with multiple staff members.
- If the caller asks to speak to a specific person: "I'll make sure they get your message and call you back directly."
- If the caller says they've spoken to someone before: "Of course — I'll pass your details straight to them."
- Never promise to "transfer" or "put them through" — you are the receptionist taking messages.` : '';

  const afterHoursNote = after_hours_only
    ? `\nIMPORTANT: You are the after-hours service. The business is currently closed. Don't apologise for this — it's expected. Your job is to make sure the caller feels heard and that someone will get back to them.`
    : '';

  return `You are ${receptionist}, a warm and professional AI receptionist for ${business_name}, a ${industry} business.${afterHoursNote}

BUSINESS INFORMATION:
- Hours: ${biz_hours || 'Monday to Friday 8am–6pm'}
- Address: ${biz_address || 'Please call us for our location'}
- Pricing: ${biz_pricing || 'Pricing depends on the job — we give free quotes'}
- Payment: Cash and card accepted
- Emergencies: Yes — leave your number and someone calls back within 15 minutes${hasDepts ? `\n- Departments: ${deptList.join(', ')}` : ''}

YOUR JOB: Have a natural conversation. Answer questions. Collect name, issue${hasDepts ? ', department,' : ''} and callback number.${canBook ? ' You can also book appointments.' : ''}

CONVERSATION FLOW:
- You already asked for their name. Once they give it, use it naturally.${deptRouting}
- Ask what you can help with today.
- Listen, show empathy, answer any questions from the business info above.
- Ask for their callback number including country code (e.g. "Could I get your number with the country code?"). Store it exactly as they say it.${canBook ? `
- If they want to book: ask what service/package, then preferred date and time. Confirm: "So that's [service] on [date] at [time] — shall I book that?" Once confirmed, call book_appointment with ISO 8601 time. Then say: "Perfect [name], you're booked for [service] on [date] at [time]. You'll get a confirmation text now and a reminder the day before."
- If no appointment: collect name, issue, phone and call save_lead.` : `
- Once you have all three: "Perfect [name], I've got you noted. Someone from ${business_name} will call you back on [number] shortly." Then call save_lead.`}
- Say a warm goodbye after saving or booking.
${officeContext}
HANDLING QUESTIONS:
- Pricing, hours, location: answer directly from business info. Never dodge.
- Don't know: "Great question — I'll make sure whoever calls you back can answer that."
- "Are you AI?": "I'm an AI assistant, but a real person from ${business_name} will call right back."
- Upset/urgent caller: empathy first. "Oh no, let's get someone to you as fast as we can."
- NEVER say: cannot help, don't have access, as an AI language model, I apologize for the inconvenience.

STYLE: Warm, natural, human. Contractions always. 1–2 short sentences per reply. This is a phone call.${plan === 'pro' ? '\n\nSTAFF DIRECTORY: If a caller asks to speak to someone specific or reach a department, use the route_to_staff tool. Do NOT guess — let the tool look them up.' : ''}${hold_message ? `\n\nON-HOLD MESSAGE: If you ever need to put someone on hold or let them know there's a wait, say: "${hold_message}"` : ''}`;
}

// =============================================================
//  ASSIGN PHONE NUMBER
// =============================================================
async function assignPhoneNumber(assistantId, ownerPhone) {
  const country = countryCodeFromPhone(ownerPhone);
  try {
    const r = await fetch('https://api.vapi.ai/phone-number', {
      method:  'POST',
      headers: { Authorization: `Bearer ${process.env.VAPI_API_KEY}`, 'Content-Type': 'application/json' },
      body:    JSON.stringify({
        provider:         'twilio',
        twilioAccountSid: process.env.TWILIO_ACCOUNT_SID,
        twilioAuthToken:  process.env.TWILIO_AUTH_TOKEN,
        assistantId,
        ...(country !== 'US' && { country }),
      })
    });
    const data = await r.json();
    if (!r.ok) throw new Error(JSON.stringify(data));
    console.log(`[vapi] phone assigned: ${data.number}`);
    return data.number;
  } catch (err) {
    console.warn('[vapi] phone buy failed:', err.message);
    return process.env.DEFAULT_MISSEDCALL_NUMBER || null;
  }
}

if (!process.env.VAPI_WEBHOOK_SECRET) {
  console.warn('[startup] VAPI_WEBHOOK_SECRET not set — Vapi webhook is unauthenticated');
}

// Plan call limits
const PLAN_CALL_LIMITS = { starter: 100, growth: 500 };

// =============================================================
//  VAPI WEBHOOK — HMAC verify signature, handle events
// =============================================================
app.post('/vapi/webhook/:businessId', async (req, res) => {
  // HMAC signature check — always runs when secret is set
  if (process.env.VAPI_WEBHOOK_SECRET) {
    const sig = req.headers['x-vapi-signature'];
    const expected = crypto
      .createHmac('sha256', process.env.VAPI_WEBHOOK_SECRET)
      .update(req.rawBody || Buffer.from(JSON.stringify(req.body)))
      .digest('hex');
    if (sig !== expected) {
      console.warn('[webhook] rejected — bad HMAC signature');
      return res.status(401).json({ error: 'Unauthorized' });
    }
  }

  const { message }    = req.body;
  const { businessId } = req.params;
  if (!message) return res.json({ result: 'ok' });

  const { type, call } = message;
  const callId = call?.id;

  try {
    if (type === 'tool-calls') {
      const { data: biz } = await supabase
        .from('businesses')
        .select('status, trial_ends_at, plan, calls_this_month, aria_paused, past_due_at')
        .eq('id', businessId)
        .single();

      if (biz?.aria_paused) {
        const results = (message.toolCallList || []).map(tc => ({
          toolCallId: tc.id,
          result: JSON.stringify({ success: false, message: "I'm sorry, our team is temporarily unavailable. Please call back later or leave a message." })
        }));
        return res.json({ results });
      }

      if (biz && isExpired(biz)) {
        console.warn(`[webhook] suspended business ${businessId}`);
        const results = (message.toolCallList || []).map(tc => ({
          toolCallId: tc.id,
          result: JSON.stringify({ success: false, error: 'Account suspended' })
        }));
        return res.json({ results });
      }

      // Call volume enforcement
      if (biz && PLAN_CALL_LIMITS[biz.plan] !== undefined) {
        const limit = PLAN_CALL_LIMITS[biz.plan];
        if ((biz.calls_this_month || 0) >= limit) {
          console.warn(`[webhook] call limit reached for business ${businessId} (plan: ${biz.plan}, count: ${biz.calls_this_month})`);
          const results = (message.toolCallList || []).map(tc => ({
            toolCallId: tc.id,
            result: JSON.stringify({ success: false, message: "We've reached our capacity for this month. Please call back next month or contact us directly — we're sorry for the inconvenience." })
          }));
          return res.json({ results });
        }
      }

      const results = [];
      for (const tc of message.toolCallList || []) {
        let result;
        try {
          const args   = tc.function.arguments || tc.function.parameters || {};
          const params = typeof args === 'string' ? JSON.parse(args) : args;
          if (tc.function.name === 'save_lead') {
            result = await saveLead(businessId, callId, call, params);
          } else if (tc.function.name === 'book_appointment') {
            result = await saveAppointment(businessId, callId, call, params);
          } else if (tc.function.name === 'route_to_staff') {
            result = await routeToStaff(businessId, callId, call, params);
          }
        } catch (err) {
          console.error('[webhook] tool error:', err.message);
          result = { success: false, error: err.message };
        }
        results.push({ toolCallId: tc.id, result: JSON.stringify(result) });
      }
      return res.json({ results });
    }

    if (type === 'call-started') {
      console.log(`[call] started ${callId} (biz: ${businessId})`);
      await supabase.from('calls').insert({
        id:            callId,
        business_id:   businessId,
        caller_number: call?.customer?.number || null,
        started_at:    new Date().toISOString(),
        status:        'in_progress'
      });
      // Increment monthly call counter
      const { data: bizCount } = await supabase.from('businesses')
        .select('calls_this_month').eq('id', businessId).single();
      await supabase.from('businesses')
        .update({ calls_this_month: (bizCount?.calls_this_month || 0) + 1 })
        .eq('id', businessId);
    }

    if (type === 'call-ended') {
      console.log(`[call] ended ${callId} (${call?.duration || 0}s)`);
      const recordingUrl = call?.recordingUrl || null;
      const duration = call?.duration || null;

      // Build readable transcript from Vapi message array
      const rawMessages = message?.artifact?.messages || call?.messages || [];
      const transcript = rawMessages
        .filter(m => m.role === 'assistant' || m.role === 'user')
        .map(m => `${m.role === 'assistant' ? 'Aria' : 'Caller'}: ${m.message || m.content || ''}`)
        .join('\n') || null;

      await supabase.from('calls').update({
        status:           'completed',
        ended_at:         new Date().toISOString(),
        duration_seconds: duration,
        recording_url:    recordingUrl,
        transcript,
      }).eq('id', callId);

      if (recordingUrl) {
        const { data: biz } = await supabase.from('businesses')
          .select('business_name, email, voicemail_email').eq('id', businessId).single();
        const { count: leadCount } = await supabase.from('leads')
          .select('id', { count: 'exact', head: true }).eq('call_id', callId);
        const { count: apptCount } = await supabase.from('appointments')
          .select('id', { count: 'exact', head: true }).eq('call_id', callId);

        if ((!leadCount && !apptCount) && biz && process.env.RESEND_API_KEY) {
          const sendTo = biz.voicemail_email || biz.email;
          const callerNum = call?.customer?.number || 'Unknown';
          await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              from: `MissedCallio <noreply@${process.env.EMAIL_DOMAIN || 'missedcallio.io'}>`,
              to: sendTo,
              subject: `Voicemail from ${callerNum} — ${biz.business_name}`,
              html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
                <h2 style="color:#ff5c00">You have a voicemail</h2>
                <p>A caller hung up before leaving details. Duration: ${duration || 0}s.</p>
                <p><strong>Caller:</strong> ${callerNum}</p>
                <br/>
                <a href="${recordingUrl}" style="background:#ff5c00;color:white;padding:12px 28px;border-radius:99px;text-decoration:none;font-weight:500">
                  Listen to recording →
                </a>
                <br/><br/>
                <p style="color:#888">— MissedCallio</p>
              </div>`
            })
          });
          console.log(`[voicemail] emailed recording for call ${callId} to ${sendTo}`);
        }
      }
    }

  } catch (err) {
    console.error('[webhook] error:', err.message);
  }

  return res.json({ result: 'ok' });
});

function isExpired(biz) {
  if (biz.status === 'active') return false;
  if (biz.status === 'trial' && biz.trial_ends_at) {
    return new Date(biz.trial_ends_at) < new Date();
  }
  if (biz.status === 'past_due') {
    // Give a 5-day grace period before cutting off service
    if (!biz.past_due_at) return false;
    const graceDays = 5;
    return (Date.now() - new Date(biz.past_due_at).getTime()) > graceDays * 24 * 60 * 60 * 1000;
  }
  return biz.status === 'cancelled';
}

// =============================================================
//  SAVE LEAD
// =============================================================
async function saveLead(businessId, callId, call, { name, issue, phone }) {
  if (!name || !phone) return { success: false, error: 'Missing name or phone' };

  const { data: business } = await supabase
    .from('businesses').select('business_name, mobile_number, slack_webhook_url, departments').eq('id', businessId).single();

  const { data: teamMembers } = await supabase
    .from('team_members')
    .select('name, role, phone, notify_sms')
    .eq('business_id', businessId)
    .eq('notify_sms', true);

  const lead = {
    business_id:   businessId,
    call_id:       callId,
    name,
    issue:         issue || 'Not specified',
    phone:         normalizePhone(phone),
    caller_number: call?.customer?.number || null,
    received_at:   new Date().toISOString()
  };

  const { error } = await supabase.from('leads').insert(lead);
  if (error) console.error('[lead] insert error:', error.message);
  await fireWebhook(businessId, 'lead.created', lead);

  // In-app notification
  supabase.from('notifications').insert({
    business_id: businessId,
    type:  'lead',
    title: `New lead: ${name}`,
    body:  `${phone} — ${issue || 'No reason given'}`,
  }).then(() => {}).catch(() => {});

  // HubSpot CRM push
  if (!error && business?.hubspot_api_key) {
    pushLeadToHubSpot(business.hubspot_api_key, lead).catch(() => {});
  }

  // First-lead milestone email
  if (!error && process.env.RESEND_API_KEY) {
    const { count: totalLeads } = await supabase.from('leads')
      .select('id', { count: 'exact', head: true }).eq('business_id', businessId);
    if (totalLeads === 1) {
      const { data: biz } = await supabase.from('businesses')
        .select('email, name, business_name').eq('id', businessId).single();
      if (biz) {
        fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from:    `MissedCallio <noreply@${process.env.EMAIL_DOMAIN || 'missedcallio.io'}>`,
            to:      biz.email,
            subject: `🎉 Aria just captured your first lead — ${lead.name}`,
            html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
              <h2 style="color:#ff5c00">Your first lead is in!</h2>
              <p>Hi ${biz.name},</p>
              <p>Aria just answered a call for <strong>${biz.business_name}</strong> and captured your first lead:</p>
              <table style="width:100%;margin:20px 0;border-collapse:collapse">
                <tr><td style="padding:8px 0;color:#888;font-size:14px">Name</td><td style="padding:8px 0;font-weight:500">${lead.name}</td></tr>
                <tr><td style="padding:8px 0;color:#888;font-size:14px">Phone</td><td style="padding:8px 0;font-weight:500">${lead.phone}</td></tr>
                <tr><td style="padding:8px 0;color:#888;font-size:14px">Reason</td><td style="padding:8px 0;font-weight:500">${lead.issue}</td></tr>
              </table>
              <p>Every missed call from here on is a captured lead. Check your dashboard to see more.</p>
              <br/>
              <a href="${process.env.SERVER_URL || 'https://missedcallio.online'}/dashboard"
                 style="background:#ff5c00;color:white;padding:12px 28px;border-radius:99px;text-decoration:none;font-weight:500;display:inline-block">
                View Dashboard →
              </a>
              <br/><br/><p style="color:#888">— The MissedCallio Team</p>
              ${emailFooter(biz.email)}
            </div>`
          })
        }).catch(() => {});
        console.log(`[milestone] first-lead email sent to ${biz.email}`);
      }
    }
  }

  if (business) {
    await sendSMSToOwner(business, lead);

    if (business.slack_webhook_url) {
      await sendSlack(business.slack_webhook_url,
        `📞 *New lead — ${business.business_name}*\n*Name:* ${name}\n*Phone:* ${lead.phone}\n*Issue:* ${issue}`);
    }

    if (teamMembers && teamMembers.length > 0) {
      const issueLower = (lead.issue || '').toLowerCase();
      const relevantMembers = teamMembers.filter(m => {
        if (!m.role) return true;
        return issueLower.includes(m.role.toLowerCase());
      });
      const toNotify = relevantMembers.length > 0 ? relevantMembers : teamMembers;
      await Promise.all(toNotify.map(member => sendSMSToTeamMember(member, business, lead)));
    }
  }

  console.log(`[lead] saved: ${name} | ${phone}`);
  return { success: true };
}

// =============================================================
//  SMS TO TEAM MEMBER
// =============================================================
async function sendSMSToTeamMember(member, business, lead) {
  if (!process.env.TWILIO_ACCOUNT_SID || !member?.phone) return;
  const time = new Date(lead.received_at).toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  await sendSMS(
    normalizePhone(member.phone),
    `New lead — ${business.business_name}\nName:  ${lead.name}\nPhone: ${lead.phone}\nIssue: ${lead.issue}\nTime:  ${time}`
  );
}

// =============================================================
//  SAVE APPOINTMENT
// =============================================================
async function saveAppointment(businessId, callId, call, { name, phone, service, appointment_time, timezone, notes }) {
  if (!name || !phone || !service || !appointment_time) {
    return { success: false, error: 'Missing required fields' };
  }

  const { data: business } = await supabase
    .from('businesses').select('business_name, mobile_number, biz_address, slack_webhook_url, timezone').eq('id', businessId).single();

  // Use provided timezone, or fall back to the business's stored timezone, then UTC
  const bizTimezone = timezone || business?.timezone || 'UTC';
  // Parse the appointment time — if it has no offset, treat it as being in bizTimezone
  // For full correctness a library like luxon is needed; for now we store as-is (UTC assumed from ISO string)
  const apptTime = new Date(appointment_time);
  if (isNaN(apptTime.getTime())) return { success: false, error: 'Invalid appointment_time' };

  const { data: appt, error } = await supabase.from('appointments').insert({
    business_id:      businessId,
    call_id:          callId,
    name,
    phone:            normalizePhone(phone),
    service,
    appointment_time: apptTime.toISOString(),
    notes:            notes || null,
    status:           'confirmed',
    reminder_sent:    false
  }).select().single();

  if (error) {
    console.error('[appt] insert error:', error.message);
    return { success: false, error: error.message };
  }

  await fireWebhook(businessId, 'appointment.created', appt);

  // In-app notification
  supabase.from('notifications').insert({
    business_id: businessId,
    type:  'appointment',
    title: `Appointment booked: ${name}`,
    body:  `${service} — ${formatApptTime(apptTime)}`,
  }).then(() => {}).catch(() => {});

  console.log(`[appt] booked: ${name} | ${service} | ${formatApptTime(apptTime)}`);

  if (business) {
    await sendAppointmentConfirmation(business, appt);
    await sendSMS(
      normalizePhone(business.mobile_number),
      `New appointment — ${business.business_name}\n` +
      `Name:    ${name}\nPhone:   ${phone}\nService: ${service}\nTime:    ${formatApptTime(apptTime)}` +
      (notes ? `\nNotes:   ${notes}` : '')
    );
    if (business.slack_webhook_url) {
      await sendSlack(business.slack_webhook_url,
        `📅 *New appointment — ${business.business_name}*\n*Name:* ${name}\n*Service:* ${service}\n*Time:* ${formatApptTime(apptTime)}\n*Phone:* ${normalizePhone(phone)}`);
    }
  }

  return { success: true, appointment_id: appt.id };
}

// =============================================================
//  TWILIO INBOUND SMS — handle CANCEL / STOP replies
// =============================================================
app.post('/twilio/sms', async (req, res) => {
  // Verify Twilio webhook signature
  const twilioAuthToken  = process.env.TWILIO_AUTH_TOKEN;
  const twilioWebhookUrl = process.env.TWILIO_WEBHOOK_URL;
  if (!twilioAuthToken || !twilioWebhookUrl) {
    console.warn('[twilio/sms] TWILIO_AUTH_TOKEN or TWILIO_WEBHOOK_URL not set — skipping signature verification (dev mode)');
  } else {
    const twilioSig = req.headers['x-twilio-signature'] || '';
    const params    = req.body || {};
    const sortedStr = Object.keys(params).sort().reduce((acc, k) => acc + k + params[k], '');
    const expected  = crypto.createHmac('sha1', twilioAuthToken)
      .update(twilioWebhookUrl + sortedStr)
      .digest('base64');
    const expBuf = Buffer.from(expected);
    const sigBuf = Buffer.from(twilioSig);
    const valid  = expBuf.length === sigBuf.length && crypto.timingSafeEqual(expBuf, sigBuf);
    if (!valid) {
      console.warn('[twilio/sms] rejected — bad Twilio signature');
      return res.status(403).set('Content-Type', 'text/xml')
        .send(`<?xml version="1.0" encoding="UTF-8"?><Response/>`);
    }
  }

  const from = req.body.From || '';
  const body = (req.body.Body || '').trim().toUpperCase();

  const twiml = (msg) => res
    .set('Content-Type', 'text/xml')
    .send(`<?xml version="1.0" encoding="UTF-8"?><Response><Message>${msg}</Message></Response>`);

  if (body === 'CANCEL' || body === 'STOP' || body === 'UNSUBSCRIBE') {
    const normalized = normalizePhone(from);
    const { data: appt } = await supabase
      .from('appointments')
      .select('id, name, service, appointment_time')
      .eq('phone', normalized)
      .eq('status', 'confirmed')
      .gt('appointment_time', new Date().toISOString())
      .order('appointment_time', { ascending: true })
      .limit(1)
      .single();

    if (appt) {
      await supabase.from('appointments').update({ status: 'cancelled' }).eq('id', appt.id);
      console.log(`[sms] appointment ${appt.id} cancelled by ${normalized}`);
      return twiml(`Your appointment for ${appt.service} on ${formatApptTime(new Date(appt.appointment_time))} has been cancelled. We hope to see you again soon!`);
    }
    return twiml("We couldn't find an upcoming appointment for your number. Please call us directly if you need help.");
  }

  res.set('Content-Type', 'text/xml').send(`<?xml version="1.0" encoding="UTF-8"?><Response/>`);
});

// =============================================================
//  SMS HELPERS
// =============================================================
async function sendSMSToOwner(business, lead) {
  if (!process.env.TWILIO_ACCOUNT_SID || !business?.mobile_number) return;
  const time = new Date(lead.received_at).toLocaleString('en-US', { dateStyle: 'short', timeStyle: 'short' });
  await sendSMS(
    normalizePhone(business.mobile_number),
    `New call — ${business.business_name}\nName:  ${lead.name}\nPhone: ${lead.phone}\nIssue: ${lead.issue}\nTime:  ${time}`
  );
}

async function sendAppointmentConfirmation(business, appt) {
  if (!process.env.TWILIO_ACCOUNT_SID || !appt.phone) return;
  const time    = formatApptTime(new Date(appt.appointment_time));
  const address = business.biz_address || 'our location';
  await sendSMS(
    normalizePhone(appt.phone),
    `Hi ${appt.name}! Your appointment at ${business.business_name} is confirmed.\n` +
    `Service: ${appt.service}\nWhen: ${time}\nWhere: ${address}\n` +
    `Reply CANCEL to cancel. We'll remind you the day before!`
  );
}

async function sendAppointmentReminder(business, appt) {
  if (!process.env.TWILIO_ACCOUNT_SID || !appt.phone) return;
  const time    = formatApptTime(new Date(appt.appointment_time));
  const address = business.biz_address || 'our location';
  await sendSMS(
    normalizePhone(appt.phone),
    `Reminder: Your appointment at ${business.business_name} is tomorrow!\n` +
    `Service: ${appt.service}\nWhen: ${time}\nWhere: ${address}\n` +
    `Reply CANCEL to cancel or call us to reschedule.`
  );
  console.log(`[reminder] sent to ${appt.phone} for appt #${appt.id}`);
}

async function sendSMS(to, body) {
  if (!process.env.TWILIO_ACCOUNT_SID) return;
  try {
    const creds = Buffer.from(`${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64');
    const r = await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${process.env.TWILIO_ACCOUNT_SID}/Messages.json`,
      {
        method:  'POST',
        headers: { Authorization: `Basic ${creds}`, 'Content-Type': 'application/x-www-form-urlencoded' },
        body:    new URLSearchParams({ To: to, From: process.env.TWILIO_FROM_NUMBER, Body: body })
      }
    );
    if (r.ok) console.log(`[sms] sent to ${to}`);
    else console.error('[sms] Twilio error:', await r.text());
  } catch (err) {
    console.error('[sms] failed:', err.message);
  }
}

// =============================================================
//  OUTBOUND WEBHOOK — with retry (3 attempts, exponential backoff)
// =============================================================
// =============================================================
//  HUBSPOT CRM — push lead as a contact
// =============================================================
async function pushLeadToHubSpot(apiKey, lead) {
  try {
    const r = await fetch('https://api.hubapi.com/crm/v3/objects/contacts', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        properties: {
          firstname: (lead.name || '').split(' ')[0],
          lastname:  (lead.name || '').split(' ').slice(1).join(' ') || '',
          phone:     lead.phone || lead.caller_number || '',
          hs_lead_status: 'NEW',
          description: lead.issue || '',
        }
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({}));
      console.warn('[hubspot] push failed:', JSON.stringify(err));
    } else {
      console.log(`[hubspot] contact created for ${lead.name}`);
    }
  } catch (e) {
    console.warn('[hubspot] push error:', e.message);
  }
}

async function fireWebhook(businessId, event, data) {
  try {
    const { data: biz } = await supabase.from('businesses').select('outbound_webhook_url').eq('id', businessId).single();
    if (!biz?.outbound_webhook_url) return;
    const payload = JSON.stringify({ event, data, timestamp: new Date().toISOString() });
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const r = await fetch(biz.outbound_webhook_url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: payload,
          signal: AbortSignal.timeout(8000),
        });
        if (r.ok) return;
        console.warn(`[webhook] attempt ${attempt} got ${r.status}`);
      } catch (fetchErr) {
        console.warn(`[webhook] attempt ${attempt} failed: ${fetchErr.message}`);
      }
      if (attempt < 3) await new Promise(r => setTimeout(r, attempt * 2000));
    }
    console.error(`[webhook] all 3 attempts failed for ${businessId}`);
  } catch (e) {
    console.error('[webhook] error:', e.message);
  }
}

// =============================================================
//  SLACK HELPER
// =============================================================
async function sendSlack(webhookUrl, text) {
  if (!webhookUrl) return;
  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
  } catch (err) {
    console.error('[slack] send error:', err.message);
  }
}

// =============================================================
//  ROUTE TO STAFF
// =============================================================
async function routeToStaff(businessId, callId, call, { staff_name }) {
  const { data: members } = await supabase
    .from('staff').select('*').eq('business_id', businessId).eq('active', true);

  if (!members || members.length === 0) {
    return { found: false, message: "I don't have a staff directory set up yet — let me take a message for the team." };
  }

  const query = staff_name.toLowerCase();
  const match = members.find(m =>
    m.name.toLowerCase().includes(query) ||
    (m.role && m.role.toLowerCase().includes(query))
  );

  if (!match) {
    const names = members.map(m => m.name).join(', ');
    return { found: false, message: `I couldn't find ${staff_name} — the team members I have are: ${names}. Would you like to leave a message for one of them?` };
  }

  if (match.phone && process.env.TWILIO_ACCOUNT_SID) {
    const callerNum = call?.customer?.number || 'unknown';
    await sendSMS(normalizePhone(match.phone), `MissedCallio: ${callerNum} is on the phone asking for you. Call them back asap.`);
  }

  if (match.email && !match.phone && process.env.RESEND_API_KEY) {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: `MissedCallio <noreply@${process.env.EMAIL_DOMAIN || 'missedcallio.io'}>`,
        to: match.email,
        subject: `Someone is asking for you`,
        html: `<p>A caller is on the line asking for you (${match.name}). Caller number: ${call?.customer?.number || 'unknown'}.</p>`
      })
    });
  }

  console.log(`[route] caller routed to ${match.name}`);
  return {
    found: true,
    name: match.name,
    role: match.role || 'team member',
    message: `I've alerted ${match.name} that you're calling. They'll call you back shortly — could I take your number just in case?`
  };
}

function formatApptTime(date) {
  return date.toLocaleString('en-US', {
    weekday: 'short', month: 'short', day: 'numeric', year: 'numeric',
    hour: 'numeric', minute: '2-digit', hour12: true
  });
}

// =============================================================
//  UNSUBSCRIBE — HMAC token, no DB column needed
// =============================================================
function makeUnsubToken(email) {
  return crypto.createHmac('sha256', process.env.TOKEN_SECRET).update(email).digest('hex');
}

function unsubLink(email) {
  const base = process.env.SERVER_URL || 'https://missedcallio.online';
  return `${base}/unsubscribe?email=${encodeURIComponent(email)}&token=${makeUnsubToken(email)}`;
}

function emailFooter(email) {
  return `<p style="font-size:11px;color:#aaa;margin-top:32px;text-align:center">
    MissedCallio · <a href="${unsubLink(email)}" style="color:#aaa">Unsubscribe</a>
  </p>`;
}

app.get('/unsubscribe', async (req, res) => {
  const { email, token } = req.query;
  if (!email || !token || token !== makeUnsubToken(email)) {
    return res.status(400).send('<p>Invalid unsubscribe link.</p>');
  }
  await supabase.from('businesses').update({ voicemail_email: null }).eq('email', email);
  res.send(`<html><body style="font-family:sans-serif;text-align:center;padding:60px">
    <h2>Unsubscribed</h2>
    <p>You've been removed from MissedCallio email notifications for ${email}.</p>
    <p>To manage your account visit <a href="${process.env.SERVER_URL || 'https://missedcallio.online'}/dashboard">your dashboard</a>.</p>
  </body></html>`);
});

// =============================================================
//  WELCOME EMAIL
// =============================================================
async function sendWelcomeEmail(business, phoneNumber) {
  if (!process.env.RESEND_API_KEY) return;
  const instructions = phoneNumber
    ? `Your MissedCallio number is: <strong>${phoneNumber}</strong><br/><br/>
       <strong>Activate in 30 seconds:</strong><br/>
       Go to your phone settings → Call Forwarding → Forward to <strong>${phoneNumber}</strong>`
    : `Our team will contact you within 24 hours to complete your setup.`;
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from:    `MissedCallio <noreply@${process.env.EMAIL_DOMAIN || 'missedcallio.io'}>`,
        to:      business.email,
        subject: `You're live on MissedCallio!`,
        html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
          <h2 style="color:#ff5c00">Welcome to MissedCallio!</h2>
          <p>Hi ${business.name},</p>
          <p>Your AI receptionist is set up for <strong>${business.business_name}</strong>.</p>
          <br/>${instructions}<br/><br/>
          <p>You'll get an SMS at <strong>${business.mobile_number}</strong> every time Aria captures a lead.</p>
          <p>Your <strong>7-day free trial</strong> starts now.</p>
          <br/>
          <a href="${process.env.SERVER_URL || 'https://missedcallio.online'}/dashboard"
             style="background:#ff5c00;color:white;padding:12px 28px;border-radius:99px;text-decoration:none;font-weight:500;display:inline-block">
            Access Your Dashboard →
          </a>
          <br/><br/><p style="color:#888">— The MissedCallio Team</p>
          ${emailFooter(business.email)}
        </div>`
      })
    });
    if (r.ok) console.log(`[email] welcome sent to ${business.email}`);
    else console.error('[email] error:', await r.text());
  } catch (err) {
    console.error('[email] failed:', err.message);
  }
}

// =============================================================
//  DASHBOARD AUTH — OTP-based login
// =============================================================
const TOKEN_SECRET = process.env.TOKEN_SECRET;

async function signToken(businessId) {
  const jti = crypto.randomBytes(16).toString('hex');
  const ts  = Date.now();
  const payload  = `${businessId}:${ts}:${jti}`;
  const sig      = crypto.createHmac('sha256', TOKEN_SECRET).update(payload).digest('hex');
  const token    = Buffer.from(`${payload}:${sig}`).toString('base64url');
  const expiresAt = new Date(ts + 30 * 24 * 60 * 60 * 1000).toISOString();
  await supabase.from('auth_sessions').insert({ business_id: businessId, jti, expires_at: expiresAt });
  return token;
}

async function verifyToken(token) {
  try {
    const decoded = Buffer.from(token, 'base64url').toString();
    const parts   = decoded.split(':');
    if (parts.length !== 4) return null;
    const [businessId, ts, jti, sig] = parts;
    if (Date.now() - Number(ts) > 30 * 24 * 60 * 60 * 1000) return null;
    const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(`${businessId}:${ts}:${jti}`).digest('hex');
    const sigBuf = Buffer.from(sig, 'hex');
    const expBuf = Buffer.from(expected, 'hex');
    if (sigBuf.length !== expBuf.length) return null;
    if (!crypto.timingSafeEqual(sigBuf, expBuf)) return null;
    // Check session is still active (not revoked)
    const { data: session } = await supabase
      .from('auth_sessions')
      .select('id')
      .eq('jti', jti)
      .gt('expires_at', new Date().toISOString())
      .maybeSingle();
    if (!session) return null;
    return businessId;
  } catch {
    return null;
  }
}

async function authMiddleware(req, res, next) {
  try {
    const token      = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
    const businessId = token ? await verifyToken(token) : null;
    if (!businessId) return res.status(401).json({ error: 'Unauthorized' });
    req.businessId = businessId;
    next();
  } catch (err) {
    console.error('[auth] middleware error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Step 1 — request OTP
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email is required.' });

  let { data: business } = await supabase
    .from('businesses').select('id, email').eq('email', email.toLowerCase().trim()).maybeSingle();

  if (!business) {
    const { data: member } = await supabase
      .from('team_members').select('business_id, email, name').eq('email', email.toLowerCase().trim()).maybeSingle();
    if (member) {
      const { data: biz } = await supabase
        .from('businesses').select('id, email').eq('id', member.business_id).single();
      if (biz) business = { id: biz.id, email: member.email };
    }
  }

  if (!business) {
    return res.json({ success: true, message: 'If that email is registered, a code has been sent.' });
  }

  const otp     = String(crypto.randomInt(100000, 999999));
  const expires = new Date(Date.now() + 10 * 60 * 1000).toISOString();

  await supabase.from('auth_otps').update({ used: true }).eq('email', business.email).eq('used', false);
  await supabase.from('auth_otps').insert({ email: business.email, otp, expires_at: expires });
  await sendOTPEmail(business.email, otp);

  console.log(`[auth] OTP sent to ${business.email}`);
  res.json({ success: true, message: 'A 6-digit code has been sent to your email.' });
});

// Step 2 — verify OTP → issue token
app.post('/api/auth/verify', authLimiter, async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'Email and code are required.' });

  const { data: record } = await supabase
    .from('auth_otps')
    .select('*')
    .eq('email', email.toLowerCase().trim())
    .eq('otp', String(otp).trim())
    .eq('used', false)
    .gte('expires_at', new Date().toISOString())
    .order('created_at', { ascending: false })
    .limit(1)
    .single();

  if (!record) {
    return res.status(401).json({ error: 'Invalid or expired code. Please request a new one.' });
  }

  await supabase.from('auth_otps').update({ used: true }).eq('id', record.id);

  const normalizedEmail = email.toLowerCase().trim();

  let { data: business } = await supabase
    .from('businesses')
    .select('id, name, business_name, email, plan, status, trial_ends_at, missedcall_number')
    .eq('email', normalizedEmail)
    .maybeSingle();

  if (!business) {
    const { data: member } = await supabase
      .from('team_members').select('business_id, name').eq('email', normalizedEmail).maybeSingle();
    if (member) {
      const { data: biz } = await supabase
        .from('businesses')
        .select('id, name, business_name, email, plan, status, trial_ends_at, missedcall_number')
        .eq('id', member.business_id).single();
      if (biz) business = biz;
    }
  }

  if (!business) return res.status(404).json({ error: 'Account not found.' });

  const token = await signToken(business.id);
  console.log(`[auth] login verified: ${business.email}`);
  res.json({ success: true, token, business });
});

// Logout — revoke session by deleting the jti
app.delete('/auth/session', authMiddleware, async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
    if (token) {
      const decoded = Buffer.from(token, 'base64url').toString();
      const parts   = decoded.split(':');
      if (parts.length === 4) {
        const jti = parts[2];
        await supabase.from('auth_sessions').delete().eq('jti', jti);
      }
    }
    res.json({ success: true });
  } catch (err) {
    console.error('[auth] logout error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
});

async function sendOTPEmail(email, otp) {
  if (!process.env.RESEND_API_KEY) {
    console.log(`[auth] OTP for ${email}: ${otp}`);
    return;
  }
  try {
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from:    `MissedCallio <noreply@${process.env.EMAIL_DOMAIN || 'missedcallio.io'}>`,
        to:      email,
        subject: `Your MissedCallio login code: ${otp}`,
        html: `<div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:32px">
          <h2 style="color:#ff5c00">Your login code</h2>
          <p style="font-size:48px;font-weight:bold;letter-spacing:12px;text-align:center;margin:24px 0">${otp}</p>
          <p style="color:#666;text-align:center">This code expires in 10 minutes. Don't share it with anyone.</p>
        </div>`
      })
    });
  } catch (err) {
    console.error('[auth] OTP email failed:', err.message);
  }
}

// =============================================================
//  SETTINGS UPDATE
// =============================================================
app.post('/api/settings', authMiddleware, async (req, res) => {
  const { businessId } = req;
  const { bizHours, bizAddress, bizPricing, mobileNumber, slackWebhookUrl, voicemailEmail, holdMessage, outboundWebhookUrl, aiName, afterHoursOnly, hubspotApiKey } = req.body;
  const updates = {};
  if (bizHours    !== undefined) updates.biz_hours   = bizHours;
  if (bizAddress  !== undefined) updates.biz_address = bizAddress;
  if (bizPricing  !== undefined) updates.biz_pricing = bizPricing;
  if (mobileNumber !== undefined) updates.mobile_number = normalizePhone(mobileNumber) || mobileNumber;
  if (slackWebhookUrl !== undefined) updates.slack_webhook_url = slackWebhookUrl || null;
  if (voicemailEmail  !== undefined) updates.voicemail_email   = voicemailEmail  || null;
  if (holdMessage     !== undefined) updates.hold_message      = holdMessage      || null;
  if (outboundWebhookUrl !== undefined) updates.outbound_webhook_url = outboundWebhookUrl || null;
  if (aiName !== undefined) updates.ai_name = aiName || null;
  if (afterHoursOnly !== undefined) updates.after_hours_only = !!afterHoursOnly;
  if (hubspotApiKey !== undefined) updates.hubspot_api_key = hubspotApiKey || null;
  if (Object.keys(updates).length === 0) return res.json({ success: true });
  const { error } = await supabase.from('businesses').update(updates).eq('id', businessId);
  if (error) return res.status(500).json({ error: error.message });

  // Regenerate Vapi assistant if prompt-affecting fields changed
  const promptFields = ['biz_hours', 'biz_address', 'biz_pricing', 'hold_message', 'ai_name', 'after_hours_only'];
  const needsRegen = promptFields.some(f => f in updates);
  if (needsRegen && process.env.VAPI_API_KEY) {
    try {
      const { data: biz } = await supabase.from('businesses')
        .select('*').eq('id', businessId).single();
      if (biz?.vapi_assistant_id) {
        await fetch(`https://api.vapi.ai/assistant/${biz.vapi_assistant_id}`, {
          method:  'PATCH',
          headers: { Authorization: `Bearer ${process.env.VAPI_API_KEY}`, 'Content-Type': 'application/json' },
          body:    JSON.stringify({ model: { systemPrompt: buildSystemPrompt(biz) } }),
        });
        console.log(`[vapi] assistant prompt updated for ${businessId}`);
      }
    } catch (vapiErr) {
      console.error('[vapi] failed to update assistant prompt:', vapiErr.message);
    }
  }

  res.json({ success: true });
});

// =============================================================
//  IN-APP NOTIFICATIONS
// =============================================================
app.get('/api/notifications', authMiddleware, async (req, res) => {
  const { data, error } = await supabase
    .from('notifications')
    .select('*')
    .eq('business_id', req.businessId)
    .order('created_at', { ascending: false })
    .limit(50);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ notifications: data || [] });
});

app.post('/api/notifications/read', authMiddleware, async (req, res) => {
  const { ids } = req.body; // array of IDs, or omit to mark all read
  const query = supabase.from('notifications').update({ read: true }).eq('business_id', req.businessId);
  if (Array.isArray(ids) && ids.length > 0) query.in('id', ids);
  await query;
  res.json({ success: true });
});

// =============================================================
//  REFERRAL INFO
// =============================================================
app.get('/api/referrals', authMiddleware, async (req, res) => {
  const { data: biz } = await supabase
    .from('businesses')
    .select('referral_code')
    .eq('id', req.businessId)
    .single();
  if (!biz) return res.status(404).json({ error: 'Not found' });

  const { count } = await supabase
    .from('businesses')
    .select('id', { count: 'exact', head: true })
    .eq('referred_by_code', biz.referral_code);

  const base = process.env.SERVER_URL || 'https://missedcallio.online';
  res.json({
    referralCode: biz.referral_code,
    referralLink: `${base}/?ref=${biz.referral_code}`,
    referralCount: count ?? 0,
  });
});

// =============================================================
//  DASHBOARD DATA
// =============================================================
app.get('/api/dashboard', authMiddleware, async (req, res) => {
  const { businessId } = req;
  const page  = Math.max(0, parseInt(req.query.page  || '0'));
  const limit = 200;
  const today = new Date().toISOString().slice(0, 10);

  const sevenDaysAgo = new Date(Date.now() - 7*24*60*60*1000).toISOString();

  const [bizResult, leadsResult, callsResult, apptsResult, returningResult, statResult, recentCallsResult] = await Promise.all([
    supabase.from('businesses')
      .select('id, name, business_name, email, plan, status, trial_ends_at, missedcall_number, mobile_number, biz_hours, biz_address, biz_pricing, slack_webhook_url, voicemail_email, hold_message, onboarding_complete, outbound_webhook_url, ai_name, aria_paused, after_hours_only, hubspot_api_key, referral_code, referred_by_code, created_at')
      .eq('id', businessId).single(),
    supabase.from('leads').select('*', { count: 'exact' })
      .eq('business_id', businessId).order('received_at', { ascending: false })
      .range(page * limit, page * limit + limit - 1),
    supabase.from('calls').select('*', { count: 'exact' })
      .eq('business_id', businessId).order('started_at', { ascending: false })
      .range(page * limit, page * limit + limit - 1),
    supabase.from('appointments').select('*', { count: 'exact' })
      .eq('business_id', businessId).order('appointment_time', { ascending: false })
      .range(page * limit, page * limit + limit - 1),
    supabase.rpc('count_returning_callers', { biz_id: businessId }),
    Promise.all([
      supabase.from('leads').select('id', { count: 'exact', head: true })
        .eq('business_id', businessId).gte('received_at', today),
      supabase.from('calls').select('id', { count: 'exact', head: true })
        .eq('business_id', businessId).gte('started_at', today),
    ]),
    supabase.from('calls').select('started_at').eq('business_id', businessId).gte('started_at', sevenDaysAgo),
  ]);

  if (bizResult.error) return res.status(500).json({ error: bizResult.error.message });

  const leads        = leadsResult.data  || [];
  const calls        = callsResult.data  || [];
  const appointments = apptsResult.data  || [];

  const phoneCounts = {};
  for (const l of leads) if (l.phone) phoneCounts[l.phone] = (phoneCounts[l.phone] || 0) + 1;
  const leadsWithReturning = leads.map(l => ({ ...l, returning: l.phone && phoneCounts[l.phone] > 1 }));

  const [leadsToday, callsToday] = statResult;
  const recentCalls = recentCallsResult.data || [];
  const callsByDay = Array.from({length:7}, (_, i) => {
    const d = new Date(Date.now() - (6-i)*24*60*60*1000);
    const dateStr = d.toISOString().slice(0,10);
    return { date: dateStr, label: d.toLocaleDateString('en', {weekday:'short'}), count: recentCalls.filter(c => c.started_at?.slice(0,10) === dateStr).length };
  });

  const totalLeadsCount = leadsResult.count ?? leads.length;
  const totalApptsCount = apptsResult.count ?? appointments.length;
  const conversionRate = totalLeadsCount > 0 ? ((totalApptsCount / totalLeadsCount) * 100).toFixed(1) : '0.0';

  const stats = {
    totalLeads:        leadsResult.count       ?? leads.length,
    totalCalls:        callsResult.count       ?? calls.length,
    totalAppointments: apptsResult.count       ?? appointments.length,
    leadsToday:        leadsToday.count        ?? 0,
    callsToday:        callsToday.count        ?? 0,
    returningCallers:  returningResult.data    ?? Object.values(phoneCounts).filter(n => n > 1).length,
    avgDuration:       calls.length ? Math.round(calls.reduce((s, c) => s + (c.duration_seconds || 0), 0) / calls.length) : 0,
    conversionRate,
    leadVsAppt: { leads: totalLeadsCount, appointments: totalApptsCount },
  };

  res.json({
    business:    bizResult.data,
    leads:       leadsWithReturning,
    calls,
    appointments,
    stats,
    callsByDay,
    pagination: {
      page,
      limit,
      totalLeads:        leadsResult.count  ?? leads.length,
      totalCalls:        callsResult.count  ?? calls.length,
      totalAppointments: apptsResult.count  ?? appointments.length,
    }
  });
});

// =============================================================
//  STAFF DIRECTORY CRUD
// =============================================================
app.get('/api/staff', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('staff')
    .select('*').eq('business_id', req.businessId).eq('active', true).order('name');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ staff: data });
});

app.post('/api/staff', authMiddleware, async (req, res) => {
  // Staff directory is a Pro-plan feature
  const { data: planCheck } = await supabase.from('businesses').select('plan').eq('id', req.businessId).single();
  if (planCheck?.plan !== 'pro') return res.status(403).json({ error: 'Staff directory is available on the Pro plan.' });
  const { name, role, phone, email } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required.' });
  const { data, error } = await supabase.from('staff').insert({
    business_id: req.businessId,
    name, role: role || null,
    phone: phone ? normalizePhone(phone) : null,
    email: email || null
  }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, member: data });
});

app.delete('/api/staff/:id', authMiddleware, async (req, res) => {
  const { error } = await supabase.from('staff')
    .update({ active: false })
    .eq('id', req.params.id)
    .eq('business_id', req.businessId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// =============================================================
//  TEAM MEMBERS CRUD (authenticated dashboard routes)
// =============================================================
app.get('/api/team', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('team_members')
    .select('id, email, name, role, phone, notify_sms, created_at')
    .eq('business_id', req.businessId).order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ members: data });
});

app.post('/api/team', authMiddleware, async (req, res) => {
  const { email, name, role } = req.body;
  if (!email || !email.includes('@')) return res.status(400).json({ error: 'Valid email required.' });

  const { data: existing } = await supabase.from('team_members')
    .select('id').eq('email', email).maybeSingle();
  if (existing) return res.status(400).json({ error: 'This email is already a team member.' });

  const { data: biz } = await supabase.from('businesses')
    .select('business_name').eq('id', req.businessId).single();

  const { error } = await supabase.from('team_members').insert({
    business_id: req.businessId,
    email, name: name || null, role: role || 'member'
  });
  if (error) return res.status(500).json({ error: error.message });

  if (process.env.RESEND_API_KEY) {
    const dashUrl = process.env.SERVER_URL || 'https://missedcallio.online';
    await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: `MissedCallio <noreply@${process.env.EMAIL_DOMAIN || 'missedcallio.io'}>`,
        to: email,
        subject: `You've been added to ${biz?.business_name || 'a MissedCallio account'}`,
        html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
          <h2 style="color:#ff5c00">You're on the team!</h2>
          <p>Hi${name ? ' ' + name : ''},</p>
          <p>You've been added as a team member on the <strong>${biz?.business_name || ''}</strong> MissedCallio account.</p>
          <p>Log in with your email address at:</p>
          <br/>
          <a href="${dashUrl}/dashboard" style="background:#ff5c00;color:white;padding:12px 28px;border-radius:99px;text-decoration:none;font-weight:500">
            Open dashboard →
          </a>
          <br/><br/>
          <p style="color:#888">— The MissedCallio Team</p>
        </div>`
      })
    });
  }

  res.json({ success: true });
});

app.delete('/api/team/:id', authMiddleware, async (req, res) => {
  const { error } = await supabase.from('team_members')
    .delete().eq('id', req.params.id).eq('business_id', req.businessId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// Middleware for /team/:businessId routes — verifies JWT and that decoded business_id matches param
async function teamAuthMiddleware(req, res, next) {
  try {
    const token          = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const tokenBusinessId = await verifyToken(token);
    if (!tokenBusinessId) return res.status(401).json({ error: 'Unauthorized' });
    if (tokenBusinessId !== req.params.businessId) return res.status(403).json({ error: 'Forbidden' });
    req.businessId = tokenBusinessId;
    next();
  } catch (err) {
    console.error('[team-auth] error:', err.message);
    res.status(500).json({ error: 'Internal server error' });
  }
}

// Team member routes (direct businessId param — authenticated)
app.post('/team/:businessId', teamAuthMiddleware, async (req, res) => {
  const { businessId } = req.params;
  const { name, role, phone, email, notify_sms } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required.' });
  const { data, error } = await supabase.from('team_members')
    .insert({ business_id: businessId, name, role: role || null, phone: phone || null, email: email || null, notify_sms: notify_sms !== false })
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, member: data });
});

app.get('/team/:businessId', teamAuthMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('team_members')
    .select('*').eq('business_id', req.params.businessId).order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ members: data });
});

app.delete('/team/:businessId/:memberId', teamAuthMiddleware, async (req, res) => {
  const { error } = await supabase.from('team_members')
    .delete().eq('id', req.params.memberId).eq('business_id', req.params.businessId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

app.patch('/team/:businessId/:memberId', teamAuthMiddleware, async (req, res) => {
  const allowed = ['name','role','phone','email','notify_sms'];
  const updates = Object.fromEntries(Object.entries(req.body).filter(([k]) => allowed.includes(k)));
  const { data, error } = await supabase.from('team_members')
    .update(updates).eq('id', req.params.memberId).eq('business_id', req.params.businessId)
    .select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, member: data });
});

// =============================================================
//  ONBOARDING COMPLETE
// =============================================================
app.patch('/api/onboarding/complete', authMiddleware, async (req, res) => {
  const { error } = await supabase.from('businesses')
    .update({ onboarding_complete: true }).eq('id', req.businessId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true });
});

// =============================================================
//  CSV EXPORT
// =============================================================
app.get('/api/leads/export', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('leads').select('*')
    .eq('business_id', req.businessId).order('received_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  const rows = data || [];
  const header = 'Name,Phone,Issue,Caller Number,Received At\n';
  const csv = header + rows.map(r =>
    [r.name, r.phone, r.issue, r.caller_number, r.received_at]
      .map(v => `"${String(v||'').replace(/"/g,'""')}"`)
      .join(',')
  ).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=leads.csv');
  res.send(csv);
});

app.get('/api/calls/export', authMiddleware, async (req, res) => {
  const { data, error } = await supabase.from('calls').select('*')
    .eq('business_id', req.businessId).order('started_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  const rows = data || [];
  const header = 'Caller Number,Status,Duration (s),Started At,Ended At,Recording URL\n';
  const csv = header + rows.map(r =>
    [r.caller_number, r.status, r.duration_seconds, r.started_at, r.ended_at, r.recording_url]
      .map(v => `"${String(v||'').replace(/"/g,'""')}"`)
      .join(',')
  ).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=calls.csv');
  res.send(csv);
});

// =============================================================
//  MANIFEST.JSON
// =============================================================
app.get('/manifest.json', (_req, res) => res.sendFile('manifest.json', { root: __dirname }));

// =============================================================
//  ADMIN ENDPOINTS — header-only key, never query param
// =============================================================
function adminAuth(req, res, next) {
  const key = req.headers['x-admin-key'];
  if (!key || key !== process.env.ADMIN_KEY) return res.status(403).json({ error: 'Forbidden' });
  next();
}

app.get('/admin/businesses', adminAuth, async (_req, res) => {
  const { data, error } = await supabase.from('businesses')
    .select('id, name, email, business_name, plan, status, trial_ends_at, created_at, industry')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ total: data.length, businesses: data });
});

app.get('/admin/leads/:businessId', adminAuth, async (req, res) => {
  const { data, error } = await supabase.from('leads').select('*')
    .eq('business_id', req.params.businessId).order('received_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ total: data.length, leads: data });
});

app.get('/admin/calls/:businessId', adminAuth, async (req, res) => {
  const { data, error } = await supabase.from('calls').select('*')
    .eq('business_id', req.params.businessId).order('started_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ total: data.length, calls: data });
});

// =============================================================
//  PAUSE / RESUME ARIA
// =============================================================
app.post('/api/aria/pause', authMiddleware, async (req, res) => {
  const { error } = await supabase.from('businesses').update({ aria_paused: true }).eq('id', req.businessId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, paused: true });
});

app.post('/api/aria/resume', authMiddleware, async (req, res) => {
  const { error } = await supabase.from('businesses').update({ aria_paused: false }).eq('id', req.businessId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ success: true, paused: false });
});

// =============================================================
//  PADDLE BILLING WEBHOOK
// =============================================================
app.post('/paddle/webhook', (req, res) => handlePaddleWebhook(req, res, supabase, req.rawBody));

app.get('/api/subscription/portal', authMiddleware, async (req, res) => {
  if (!process.env.PADDLE_API_KEY) return res.status(503).json({ error: 'Billing not configured.' });
  const { data: biz } = await supabase.from('businesses')
    .select('paddle_customer_id, paddle_subscription_id, plan').eq('id', req.businessId).single();
  if (!biz?.paddle_customer_id) {
    return res.status(400).json({ error: 'No billing account found. Complete your trial setup first.' });
  }
  try {
    const paddleEnv = process.env.PADDLE_ENV === 'sandbox' ? 'sandbox' : 'production';
    const apiBase   = paddleEnv === 'sandbox' ? 'https://sandbox-api.paddle.com' : 'https://api.paddle.com';
    const r = await fetch(`${apiBase}/customers/${biz.paddle_customer_id}/portal-sessions`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${process.env.PADDLE_API_KEY}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ subscription_ids: biz.paddle_subscription_id ? [biz.paddle_subscription_id] : [] }),
    });
    const data = await r.json();
    if (!r.ok) return res.status(500).json({ error: 'Could not open billing portal. Please contact support.' });
    res.json({ url: data.data?.urls?.general?.overview || data.data?.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/subscription/cancel', authMiddleware, async (req, res) => {
  const { data: biz } = await supabase.from('businesses')
    .select('paddle_subscription_id, plan').eq('id', req.businessId).single();
  if (!biz?.paddle_subscription_id) return res.status(400).json({ error: 'No active subscription found.' });
  const result = await cancelPaddleSubscription(biz.paddle_subscription_id);
  if (!result.success) return res.status(500).json({ error: result.error });
  res.json({ success: true, message: 'Subscription will cancel at end of billing period.' });
});

// =============================================================
//  ACCOUNT DELETION — right to erasure (GDPR)
// =============================================================
app.delete('/api/account', authMiddleware, async (req, res) => {
  try {
    const businessId = req.businessId;
    // Cancel active Paddle subscription first (best-effort)
    const { data: biz } = await supabase.from('businesses')
      .select('paddle_subscription_id, email, business_name').eq('id', businessId).single();
    if (biz?.paddle_subscription_id) {
      await cancelPaddleSubscription(biz.paddle_subscription_id).catch(() => {});
    }
    // Delete all child records first, then the business row
    await supabase.from('leads').delete().eq('business_id', businessId);
    await supabase.from('calls').delete().eq('business_id', businessId);
    await supabase.from('appointments').delete().eq('business_id', businessId);
    await supabase.from('staff').delete().eq('business_id', businessId);
    await supabase.from('team_members').delete().eq('business_id', businessId);
    await supabase.from('auth_sessions').delete().eq('business_id', businessId);
    await supabase.from('businesses').delete().eq('id', businessId);
    console.log(`[account] deleted business ${businessId} (${biz?.email})`);
    res.json({ success: true });
  } catch (err) {
    console.error('[account] delete error:', err.message);
    res.status(500).json({ error: 'Failed to delete account. Please contact support.' });
  }
});

// =============================================================
//  SEO — robots.txt and sitemap.xml
// =============================================================
// =============================================================
//  OG IMAGE — served as SVG (Twitter, LinkedIn, Slack, iMessage)
// =============================================================
app.get('/og-image', (_req, res) => {
  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  res.send(`<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="#0d0d0d"/>
      <stop offset="100%" stop-color="#1a1005"/>
    </linearGradient>
    <linearGradient id="glow" cx="50%" cy="50%" r="50%" fx="50%" fy="50%" id="radial" gradientUnits="objectBoundingBox">
      <stop offset="0%" stop-color="#ff5c00" stop-opacity="0.18"/>
      <stop offset="100%" stop-color="#ff5c00" stop-opacity="0"/>
    </linearGradient>
  </defs>
  <!-- Background -->
  <rect width="1200" height="630" fill="url(#bg)"/>
  <!-- Glow blob -->
  <ellipse cx="600" cy="315" rx="480" ry="280" fill="url(#radial)"/>
  <!-- Phone icon circle -->
  <circle cx="600" cy="180" r="64" fill="#ff5c00" opacity="0.12"/>
  <circle cx="600" cy="180" r="48" fill="#ff5c00" opacity="0.2"/>
  <!-- Phone icon -->
  <text x="600" y="200" font-size="52" text-anchor="middle" fill="#ff5c00">📞</text>
  <!-- Brand -->
  <text x="600" y="305" font-family="Georgia, serif" font-size="68" font-weight="700" text-anchor="middle" fill="#ffffff" letter-spacing="-1">Missed<tspan fill="#ff5c00">Callio</tspan></text>
  <!-- Tagline -->
  <text x="600" y="365" font-family="Arial, sans-serif" font-size="28" text-anchor="middle" fill="#aaaaaa" letter-spacing="0.5">AI Receptionist for Small Businesses</text>
  <!-- Divider -->
  <line x1="440" y1="400" x2="760" y2="400" stroke="#ff5c00" stroke-width="1.5" opacity="0.4"/>
  <!-- Value prop -->
  <text x="600" y="445" font-family="Arial, sans-serif" font-size="22" text-anchor="middle" fill="#888888">Answers every call · Captures leads · Books appointments</text>
  <!-- CTA pill -->
  <rect x="450" y="480" width="300" height="52" rx="26" fill="#ff5c00"/>
  <text x="600" y="513" font-family="Arial, sans-serif" font-size="20" font-weight="600" text-anchor="middle" fill="#ffffff">Start free for 7 days →</text>
  <!-- URL -->
  <text x="600" y="590" font-family="Arial, sans-serif" font-size="18" text-anchor="middle" fill="#555555">missedcallio.online</text>
</svg>`);
});

app.get('/robots.txt', (_req, res) => {
  res.type('text/plain').send(
    `User-agent: *\nAllow: /\nDisallow: /dashboard\nDisallow: /api/\nDisallow: /admin/\n\nSitemap: ${process.env.SERVER_URL || 'https://missedcallio.online'}/sitemap.xml`
  );
});

app.get('/sitemap.xml', (_req, res) => {
  const base = process.env.SERVER_URL || 'https://missedcallio.online';
  res.type('application/xml').send(
    `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${base}/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>${base}/call-forwarding</loc><changefreq>monthly</changefreq><priority>0.6</priority></url>
</urlset>`
  );
});

app.get('/status', (_req, res) => res.sendFile('status.html', { root: __dirname }));

app.get('/health', (_req, res) => res.json({
  status:  'ok',
  db:      !!process.env.SUPABASE_URL,
  vapi:    !!process.env.VAPI_API_KEY,
  twilio:  !!process.env.TWILIO_ACCOUNT_SID,
  resend:  !!process.env.RESEND_API_KEY,
  paddle:  !!process.env.PADDLE_API_KEY,
  uptime:  Math.round(process.uptime()),
}));

// =============================================================
//  REMINDER POLLER — distributed-safe via optimistic DB lock
// =============================================================
async function runReminderPoller() {
  try {
    if (process.env.TWILIO_ACCOUNT_SID) {
      const now  = new Date();
      const from = new Date(now.getTime() + 23 * 60 * 60 * 1000).toISOString();
      const to   = new Date(now.getTime() + 25 * 60 * 60 * 1000).toISOString();

      const { data: appts } = await supabase
        .from('appointments')
        .select('*, businesses(business_name, mobile_number, biz_address)')
        .eq('reminder_sent', false)
        .eq('status', 'confirmed')
        .gte('appointment_time', from)
        .lte('appointment_time', to);

      if (appts && appts.length > 0) {
        console.log(`[reminder] ${appts.length} to send`);
        for (const appt of appts) {
          const { data: updated } = await supabase
            .from('appointments')
            .update({ reminder_sent: true })
            .eq('id', appt.id)
            .eq('reminder_sent', false)
            .select('id');
          if (!updated || updated.length === 0) continue; // another instance beat us
          const business = appt.businesses;
          if (business) await sendAppointmentReminder(business, appt);
        }
      }
    }

    // Monthly call counter reset — runs on the 1st of the month (within first hour)
    const now = new Date();
    if (now.getDate() === 1 && now.getHours() < 1) {
      const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
      const { count } = await supabase.from('businesses')
        .update({ calls_this_month: 0, calls_reset_at: monthStart })
        .lt('calls_reset_at', monthStart)
        .select('id', { count: 'exact', head: true });
      if (count > 0) console.log(`[poller] monthly call counter reset for ${count} businesses`);
    }

    // Flip expired trials to 'expired' status
    if (process.env.RESEND_API_KEY) {
      const { data: expiredTrials } = await supabase
        .from('businesses')
        .update({ status: 'expired' })
        .eq('status', 'trial')
        .lt('trial_ends_at', new Date().toISOString())
        .select('id, email, business_name, name');
      if (expiredTrials && expiredTrials.length > 0) {
        const SERVER_URL = process.env.SERVER_URL || 'https://missedcallio.online';
        for (const biz of expiredTrials) {
          try {
            await fetch('https://api.resend.com/emails', {
              method: 'POST',
              headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                from: `MissedCallio <noreply@${process.env.EMAIL_DOMAIN || 'missedcallio.io'}>`,
                to: biz.email,
                subject: 'Your MissedCallio trial has ended',
                html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
                  <h2 style="color:#ff5c00">Your trial has ended</h2>
                  <p>Hi ${biz.name || biz.business_name},</p>
                  <p>Your 7-day free trial for <strong>${biz.business_name}</strong> has ended.</p>
                  <p>Upgrade now to keep Aria answering your calls. It takes under a minute.</p>
                  <br/>
                  <a href="${SERVER_URL}/#pricing"
                     style="background:#ff5c00;color:white;padding:12px 28px;border-radius:99px;text-decoration:none;font-weight:500;display:inline-block">
                    Upgrade now →
                  </a>
                  <br/><br/><p style="color:#888">— The MissedCallio Team</p>
                </div>`
              })
            });
            console.log(`[trial-expired] email sent to ${biz.email}`);
          } catch (err) {
            console.error(`[trial-expired] email failed for ${biz.email}:`, err.message);
          }
        }
      }
    }

    // Hourly OTP cleanup — delete used/expired OTPs older than 1 day
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    await supabase.from('auth_otps').delete()
      .lt('expires_at', cutoff)
      .eq('used', true);

  } catch (err) {
    console.error('[reminder] poller error:', err.message);
  }
}

setInterval(runReminderPoller, 5 * 60 * 1000);
console.log('[startup] Reminder poller started');

// =============================================================
//  TRIAL WARNING POLLER — sends 2-day warning email
// =============================================================
async function runTrialWarningPoller() {
  try {
    if (!process.env.RESEND_API_KEY) return;
    const now        = new Date();
    const windowFrom = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000).toISOString();
    const windowTo   = new Date(now.getTime() + 2.25 * 24 * 60 * 60 * 1000).toISOString();

    const { data: businesses } = await supabase
      .from('businesses').select('id, name, email, business_name, plan')
      .eq('status', 'trial')
      .gte('trial_ends_at', windowFrom)
      .lte('trial_ends_at', windowTo);

    if (!businesses || businesses.length === 0) return;

    for (const biz of businesses) {
      try {
        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from:    `MissedCallio <noreply@${process.env.EMAIL_DOMAIN || 'missedcallio.io'}>`,
            to:      biz.email,
            subject: `Your MissedCallio trial ends in 2 days`,
            html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
              <h2 style="color:#ff5c00">Your free trial ends in 2 days</h2>
              <p>Hi ${biz.name},</p>
              <p>Your 7-day free trial for <strong>${biz.business_name}</strong> on the <strong>${biz.plan}</strong> plan expires in 2 days.</p>
              <p>To keep Aria answering your calls, add a payment method before your trial ends.</p>
              <br/>
              <a href="${process.env.SERVER_URL || 'https://missedcallio.online'}/dashboard"
                 style="background:#ff5c00;color:white;padding:12px 28px;border-radius:99px;text-decoration:none;font-weight:500">
                Manage my account →
              </a>
              <br/><br/>
              <p style="color:#888">— The MissedCallio Team</p>
              ${emailFooter(biz.email)}
            </div>`
          })
        });
        console.log(`[trial-warning] sent to ${biz.email}`);
      } catch (err) {
        console.error(`[trial-warning] failed for ${biz.email}:`, err.message);
      }
    }
  } catch (err) {
    console.error('[trial-warning] poller error:', err.message);
  }
}

setInterval(runTrialWarningPoller, 60 * 60 * 1000);  // hourly

// =============================================================
//  WEEKLY DIGEST POLLER — Monday 8am UTC per business timezone
// =============================================================
async function runWeeklyDigestPoller() {
  try {
    if (!process.env.RESEND_API_KEY) return;
    const now = new Date();
    // Only run on Mondays between 8:00 and 8:59 UTC
    if (now.getUTCDay() !== 1 || now.getUTCHours() !== 8) return;

    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString();

    const { data: businesses } = await supabase
      .from('businesses')
      .select('id, name, email, business_name, status')
      .in('status', ['active', 'trial']);

    if (!businesses?.length) return;

    for (const biz of businesses) {
      try {
        const [{ count: newLeads }, { count: newCalls }] = await Promise.all([
          supabase.from('leads').select('id', { count: 'exact', head: true })
            .eq('business_id', biz.id).gte('received_at', weekAgo),
          supabase.from('calls').select('id', { count: 'exact', head: true })
            .eq('business_id', biz.id).gte('started_at', weekAgo),
        ]);

        if (!newLeads && !newCalls) continue; // skip quiet weeks

        await fetch('https://api.resend.com/emails', {
          method: 'POST',
          headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            from:    `MissedCallio <noreply@${process.env.EMAIL_DOMAIN || 'missedcallio.io'}>`,
            to:      biz.email,
            subject: `Your week with Aria — ${newLeads} lead${newLeads !== 1 ? 's' : ''} captured`,
            html: `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
              <h2 style="color:#ff5c00">Your weekly summary</h2>
              <p>Hi ${biz.name}, here's what Aria did for <strong>${biz.business_name}</strong> this week:</p>
              <table style="width:100%;margin:24px 0;border-collapse:collapse">
                <tr style="background:#f7f6f3">
                  <td style="padding:14px 18px;font-size:15px">📞 Calls answered</td>
                  <td style="padding:14px 18px;font-size:22px;font-weight:700;text-align:right">${newCalls || 0}</td>
                </tr>
                <tr>
                  <td style="padding:14px 18px;font-size:15px">👤 Leads captured</td>
                  <td style="padding:14px 18px;font-size:22px;font-weight:700;text-align:right;color:#ff5c00">${newLeads || 0}</td>
                </tr>
              </table>
              <a href="${process.env.SERVER_URL || 'https://missedcallio.online'}/dashboard"
                 style="background:#ff5c00;color:white;padding:12px 28px;border-radius:99px;text-decoration:none;font-weight:500;display:inline-block">
                View full dashboard →
              </a>
              <br/><br/><p style="color:#888">— The MissedCallio Team</p>
              ${emailFooter(biz.email)}
            </div>`
          })
        });
        console.log(`[weekly-digest] sent to ${biz.email}`);
      } catch (err) {
        console.error(`[weekly-digest] failed for ${biz.email}:`, err.message);
      }
    }
  } catch (err) {
    console.error('[weekly-digest] poller error:', err.message);
  }
}

setInterval(runWeeklyDigestPoller, 60 * 60 * 1000);  // hourly (runs only on Monday 8am UTC)

// =============================================================
//  ONBOARDING DRIP POLLER — day 1, day 3, day 6 emails
// =============================================================
async function runDripPoller() {
  if (!process.env.RESEND_API_KEY) return;
  const base = process.env.SERVER_URL || 'https://missedcallio.online';
  const now  = Date.now();

  const drips = [
    {
      flag:    'drip_day1_sent',
      minMs:   23 * 3600 * 1000,
      maxMs:   26 * 3600 * 1000,
      subject: 'Set up call forwarding in 2 minutes',
      html: (biz) => `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
        <h2 style="color:#ff5c00">One quick step to go live</h2>
        <p>Hi ${biz.name},</p>
        <p>Aria is ready to answer calls for <strong>${biz.business_name}</strong> — but she needs you to forward your missed calls to her number first.</p>
        <p>It takes about 2 minutes. <a href="${base}/call-forwarding" style="color:#ff5c00">View step-by-step instructions →</a></p>
        <p>Once you've done it, make a quick test call to your number — you should hear Aria pick up within 2 rings.</p>
        <br/>
        <a href="${base}/call-forwarding" style="background:#ff5c00;color:white;padding:12px 28px;border-radius:99px;text-decoration:none;font-weight:500;display:inline-block">Set up call forwarding →</a>
        <br/><br/><p style="color:#888">— The MissedCallio Team</p>
        ${emailFooter(biz.email)}
      </div>`,
    },
    {
      flag:    'drip_day3_sent',
      minMs:   71 * 3600 * 1000,
      maxMs:   74 * 3600 * 1000,
      subject: 'Has Aria answered a call yet?',
      html: (biz) => `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
        <h2 style="color:#ff5c00">Check in from MissedCallio</h2>
        <p>Hi ${biz.name},</p>
        <p>You're 3 days into your trial. Have you had a chance to set up call forwarding yet?</p>
        <p>If Aria has answered a call, log in to your dashboard to see the leads she's captured. If not, forwarding takes 2 minutes and she'll be live instantly.</p>
        <p><strong>Tip:</strong> If you're not sure Aria is working, call your number from another phone — she should answer within 2 rings.</p>
        <br/>
        <a href="${base}/dashboard" style="background:#ff5c00;color:white;padding:12px 28px;border-radius:99px;text-decoration:none;font-weight:500;display:inline-block">View my dashboard →</a>
        <br/><br/><p style="color:#888">— The MissedCallio Team</p>
        ${emailFooter(biz.email)}
      </div>`,
    },
    {
      flag:    'drip_day6_sent',
      minMs:   143 * 3600 * 1000,
      maxMs:   146 * 3600 * 1000,
      subject: 'Your trial ends tomorrow — keep Aria answering',
      html: (biz) => `<div style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:32px">
        <h2 style="color:#ff5c00">Your trial ends tomorrow</h2>
        <p>Hi ${biz.name},</p>
        <p>Your free trial for <strong>${biz.business_name}</strong> ends in less than 24 hours.</p>
        <p>If you'd like Aria to keep answering your calls, add a payment method now — it takes under a minute and you won't be charged until the trial ends.</p>
        <br/>
        <a href="${base}/dashboard" style="background:#ff5c00;color:white;padding:12px 28px;border-radius:99px;text-decoration:none;font-weight:500;display:inline-block">Keep Aria active →</a>
        <br/><br/><p style="color:#888">— The MissedCallio Team</p>
        ${emailFooter(biz.email)}
      </div>`,
    },
  ];

  try {
    const { data: trials } = await supabase
      .from('businesses')
      .select('id, name, email, business_name, created_at, drip_day1_sent, drip_day3_sent, drip_day6_sent')
      .eq('status', 'trial');

    if (!trials?.length) return;

    for (const biz of trials) {
      const age = now - new Date(biz.created_at).getTime();
      for (const drip of drips) {
        if (biz[drip.flag]) continue;
        if (age < drip.minMs || age > drip.maxMs) continue;
        try {
          await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              from:    `MissedCallio <noreply@${process.env.EMAIL_DOMAIN || 'missedcallio.io'}>`,
              to:      biz.email,
              subject: drip.subject,
              html:    drip.html(biz),
            }),
          });
          await supabase.from('businesses').update({ [drip.flag]: true }).eq('id', biz.id);
          console.log(`[drip] ${drip.flag} sent to ${biz.email}`);
        } catch (err) {
          console.error(`[drip] ${drip.flag} failed for ${biz.email}:`, err.message);
        }
      }
    }
  } catch (err) {
    console.error('[drip] poller error:', err.message);
  }
}

setInterval(runDripPoller, 60 * 60 * 1000);  // hourly

// =============================================================
//  START
// =============================================================
// Sentry must be added after all routes, before listen
if (process.env.SENTRY_DSN) Sentry.setupExpressErrorHandler(app);

process.on('SIGTERM', () => process.exit(0));
process.on('uncaughtException',  (e) => { if (process.env.SENTRY_DSN) Sentry.captureException(e); console.error('[fatal] uncaught:', e.message); process.exit(1); });
process.on('unhandledRejection', (e) => { if (process.env.SENTRY_DSN) Sentry.captureException(e); console.error('[fatal] unhandled:', e?.message || e); process.exit(1); });

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\nMissedCallio ✓ :${PORT}`);
  console.log(`  Supabase ${process.env.SUPABASE_URL         ? '✓' : '✗ MISSING'}`);
  console.log(`  Vapi     ${process.env.VAPI_API_KEY         ? '✓' : '- not set'}`);
  console.log(`  Twilio   ${process.env.TWILIO_ACCOUNT_SID   ? '✓' : '- not set'}`);
  console.log(`  Email    ${process.env.RESEND_API_KEY       ? '✓' : '- not set'}`);
  console.log(`  Paddle   ${process.env.PADDLE_API_KEY       ? '✓' : '- not set'}`);
  console.log(`  Webhook  ${process.env.VAPI_WEBHOOK_SECRET  ? '✓' : '- not set (unsecured)'}\n`);
});
