-- Run this in the Supabase SQL editor for missedcallio
-- Adds all columns used by server.js that may not yet exist.
-- IF NOT EXISTS means this is safe to run even if some columns already exist.

ALTER TABLE businesses
  ADD COLUMN IF NOT EXISTS email_unsubscribed   BOOLEAN     NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS timezone             TEXT,
  ADD COLUMN IF NOT EXISTS calls_reset_at       TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS calls_this_month     INTEGER     NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS ai_name              TEXT,
  ADD COLUMN IF NOT EXISTS after_hours_only     BOOLEAN     NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS aria_paused          BOOLEAN     NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS hold_message         TEXT,
  ADD COLUMN IF NOT EXISTS slack_webhook_url    TEXT,
  ADD COLUMN IF NOT EXISTS voicemail_email      TEXT,
  ADD COLUMN IF NOT EXISTS outbound_webhook_url TEXT,
  ADD COLUMN IF NOT EXISTS hubspot_api_key      TEXT,
  ADD COLUMN IF NOT EXISTS vapi_assistant_id    TEXT,
  ADD COLUMN IF NOT EXISTS vapi_phone_id        TEXT,
  ADD COLUMN IF NOT EXISTS missedcall_number    TEXT,
  ADD COLUMN IF NOT EXISTS onboarding_complete  BOOLEAN     NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS paddle_subscription_id TEXT,
  ADD COLUMN IF NOT EXISTS paddle_customer_id   TEXT,
  ADD COLUMN IF NOT EXISTS last_payment_at      TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS cancelled_at         TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS past_due_at          TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS referral_code        TEXT,
  ADD COLUMN IF NOT EXISTS referred_by_code     TEXT,
  ADD COLUMN IF NOT EXISTS drip_day1_sent       BOOLEAN     NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS drip_day3_sent       BOOLEAN     NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS drip_day6_sent       BOOLEAN     NOT NULL DEFAULT FALSE;

-- Useful indexes
CREATE INDEX IF NOT EXISTS idx_businesses_email_unsubscribed
  ON businesses (email_unsubscribed) WHERE email_unsubscribed = FALSE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_businesses_referral_code
  ON businesses (referral_code) WHERE referral_code IS NOT NULL;
