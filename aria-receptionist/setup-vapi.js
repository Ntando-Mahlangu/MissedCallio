// =============================================================
//  Run this ONCE to create Aria in Vapi
//  Open PowerShell in your folder and type: node setup-vapi.js
// =============================================================

import dotenv from 'dotenv';
import { VAPI_ASSISTANT_CONFIG } from './server.js';
dotenv.config();

const VAPI_KEY = process.env.VAPI_API_KEY;

if (!VAPI_KEY) {
  console.error('VAPI_API_KEY not set in .env');
  process.exit(1);
}

console.log('Creating Aria in Vapi...');

const res = await fetch('https://api.vapi.ai/assistant', {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${VAPI_KEY}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify(VAPI_ASSISTANT_CONFIG)
});

const data = await res.json();

if (!res.ok) {
  console.error('Vapi error:', JSON.stringify(data, null, 2));
  process.exit(1);
}

console.log('\n✅ Aria is created!');
console.log(`   Assistant ID: ${data.id}`);
console.log(`   Name: ${data.name}`);
console.log('\nNext steps:');
console.log('   1. Go to dashboard.vapi.ai');
console.log('   2. Click Phone Numbers');
console.log('   3. Buy a number and assign it to this assistant');
console.log('   4. Call the number — Aria will answer\n');