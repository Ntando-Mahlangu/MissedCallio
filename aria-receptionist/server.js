// =============================================================
//  AI Receptionist — Production Server
//  Vapi + Claude + Supabase + ElevenLabs + Twilio
// =============================================================

import express from 'express';
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

export const VAPI_ASSISTANT_CONFIG = {
  name: process.env.ARIA_NAME || 'Aria',
  model: {
    provider: 'anthropic',
    model: 'claude-sonnet-4-20250514',
    systemPrompt: buildSystemPrompt(),
    temperature: 0.7,
    maxTokens: 150,
  },
  voice: {
    provider: 'elevenlabs',
    voiceId: 'EXAVITQu4vr4xnSDxMaL',
    model: 'eleven_flash_v2_5',
    stability: 0.40,
    similarityBoost: 0.80,
    style: 0.30,
    useSpeakerBoost: true,
    optimizeStreamingLatency: 4,
  },
  transcriber: {
    provider: 'deepgram',
    model: 'nova-2',
    language: 'en',
    smartFormat: true,
    punctuate: true,
  },
  silenceTimeoutSeconds: 1.5,
  maxDurationSeconds: 300,
  firstMessage: `Hi there, thanks for calling ${process.env.BIZ_NAME || 'us'}! This is ${process.env.ARIA_NAME || 'Aria'}. Can I get your name please?`,
  endCallMessage: "Thanks so much for calling. We'll be in touch very soon. Take care!",
  endCallPhrases: ['goodbye', 'bye', 'thanks bye'],
  serverUrl: process.env.SERVER_URL + '/vapi/webhook',
  tools: [
    {
      type: 'function',
      function: {
        name: 'save_lead',
        description: "Save the caller's details once you have their name, issue, and phone number.",
        parameters: {
          type: 'object',
          required: ['name', 'issue', 'phone'],
          properties: {
            name:  { type: 'string', description: "Caller's full name" },
            issue: { type: 'string', description: 'What they need help with' },
            phone: { type: 'string', description: "Caller's callback phone number" }
          }
        }
      }
    }
  ]
};

function buildSystemPrompt() {
  return `You are ${process.env.ARIA_NAME || 'Aria'}, the receptionist for ${process.env.BIZ_NAME || 'this business'}. You answer inbound phone calls and sound like a warm, natural human being.

YOUR GOAL: Have a real conversation. Answer any question the caller has. Collect their name, issue, and callback number. Once you have all three, confirm and save.

BUSINESS INFO:
- Hours: ${process.env.BIZ_HOURS || 'Monday to Friday 8am-6pm, Saturday 9am-1pm'}
- Location: ${process.env.BIZ_ADDRESS || 'Contact us for our address'}
- Pricing: ${process.env.BIZ_PRICING || 'Pricing depends on the job - we give free quotes'}
- Payment: ${process.env.BIZ_PAYMENT || 'Cash and card accepted'}
- Emergency callouts: Yes, available. Leave your number and someone calls back within 15 minutes.

FLOW:
1. You already asked for their name. Once you have it, use it warmly.
2. Ask what you can help with today.
3. Once you know the issue, show empathy then ask for their callback number.
4. Once you have all three: "Perfect [name], I've got you noted down. Someone will call you back on [number] shortly."
5. Call save_lead immediately.

STYLE:
- Warm, natural, human. Never robotic.
- Contractions always: I'll, we'll, that's, don't, you're.
- 1-2 short sentences per reply maximum.
- Natural filler: "Sure!", "Of course.", "Got it.", "No worries."
- If asked if you're an AI: "I'm an AI assistant, but a real person will call you back - I'm just here so you don't get missed."
- NEVER say: cannot help, don't have access, as an AI language model.`;
}

app.post('/vapi/webhook', async (req, res) => {
  const { message } = req.body;
  if (!message) return res.json({ result: 'ok' });

  const { type, call } = message;
  const callId = call?.id;

  if (type === 'tool-calls') {
    const results = [];
    for (const toolCall of message.toolCallList || []) {
      let result;
      try {
        if (toolCall.function.name === 'save_lead') {
          result = await saveLead(callId, call, toolCall.function.parameters);
        }
      } catch (err) {
        console.error('save_lead error:', err.message);
        result = { success: false };
      }
      results.push({ toolCallId: toolCall.id, result: JSON.stringify(result) });
    }
    return res.json({ results });
  }

  if (type === 'call-started') {
    console.log(`Call started: ${callId} from ${call?.customer?.number || 'unknown'}`);
    await supabase.from('calls').insert({
      id: callId,
      caller_number: call?.customer?.number || null,
      started_at: new Date().toISOString(),
      status: 'in_progress'
    });
  }

  if (type === 'call-ended') {
    console.log(`Call ended: ${callId} (${call?.duration || 0}s)`);
    await supabase.from('calls').update({
      status: 'completed',
      ended_at: new Date().toISOString(),
      duration_seconds: call?.duration || null,
    }).eq('id', callId);
  }

  return res.json({ result: 'ok' });
});

async function saveLead(callId, call, { name, issue, phone }) {
  const lead = {
    call_id: callId,
    name,
    issue,
    phone,
    caller_number: call?.customer?.number || null,
    received_at: new Date().toISOString()
  };

  const { error } = await supabase.from('leads').insert(lead);
  if (error) console.error('Supabase error:', error.message);

  await notifyOwner(lead);
  console.log(`Lead saved: ${name} | ${phone} | "${issue}"`);
  return { success: true };
}

async function notifyOwner(lead) {
  if (!process.env.TWILIO_ACCOUNT_SID || !process.env.OWNER_PHONE) return;

  const time = new Date(lead.received_at).toLocaleString('en-US', {
    dateStyle: 'short', timeStyle: 'short',
    timeZone: process.env.BIZ_TIMEZONE || 'America/New_York'
  });

  const sms =
    `New call - ${process.env.BIZ_NAME || 'Receptionist'}\n` +
    `Name: ${lead.name}\n` +
    `Phone: ${lead.phone}\n` +
    `Issue: ${lead.issue}\n` +
    `Time: ${time}`;

  try {
    const creds = Buffer.from(
      `${process.env.TWILIO_ACCOUNT_SID}:${process.env.TWILIO_AUTH_TOKEN}`
    ).toString('base64');

    const res = await fetch(
      `https://api.twilio.com/2010-04-01/Accounts/${process.env.TWILIO_ACCOUNT_SID}/Messages.json`,
      {
        method: 'POST',
        headers: {
          Authorization: `Basic ${creds}`,
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({
          To: process.env.OWNER_PHONE,
          From: process.env.TWILIO_FROM_NUMBER,
          Body: sms
        })
      }
    );
    if (res.ok) console.log('SMS sent to owner');
  } catch (err) {
    console.error('SMS failed:', err.message);
  }
}

app.get('/leads', async (_req, res) => {
  const { data, error } = await supabase
    .from('leads').select('*')
    .order('received_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json({ total: data.length, leads: data });
});

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

process.on('SIGTERM', () => process.exit(0));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\nAI Receptionist running on port ${PORT}`);
  console.log(`Supabase: ${process.env.SUPABASE_URL ? 'connected' : 'MISSING'}`);
  console.log(`Twilio: ${process.env.TWILIO_ACCOUNT_SID ? 'connected' : 'MISSING'}`);
  console.log(`Owner SMS: ${process.env.OWNER_PHONE || 'NOT SET'}\n`);
});