-- Run this in the Supabase SQL editor for missedcallio
-- Adds email_unsubscribed and timezone columns to the businesses table

ALTER TABLE businesses
  ADD COLUMN IF NOT EXISTS email_unsubscribed BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS timezone TEXT;

-- Index for fast filtering of subscribed businesses in digest/drip pollers
CREATE INDEX IF NOT EXISTS idx_businesses_email_unsubscribed
  ON businesses (email_unsubscribed)
  WHERE email_unsubscribed = FALSE;
