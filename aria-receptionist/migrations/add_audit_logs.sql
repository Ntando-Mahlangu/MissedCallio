-- Audit log table — records security-sensitive actions for compliance and forensics.
-- Run in Supabase SQL editor after add_sms_suppressions.sql.

CREATE TABLE IF NOT EXISTS audit_logs (
  id          bigint generated always as identity primary key,
  business_id uuid references businesses(id) on delete cascade,
  action      text        not null,
  details     jsonb,
  ip          text,
  created_at  timestamptz not null default now()
);

CREATE INDEX IF NOT EXISTS audit_logs_biz_idx
  ON audit_logs (business_id, created_at desc);

-- Rows are append-only from the application layer.
-- The server deletes rows older than 1 year during the nightly retention purge.
