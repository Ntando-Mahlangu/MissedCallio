-- MissedCall.io SaaS Schema
-- Safe to run multiple times (uses IF NOT EXISTS)

create table if not exists businesses (
  id                  uuid default gen_random_uuid() primary key,
  name                text,
  email               text unique,
  business_name       text,
  mobile_number       text,
  industry            text,
  biz_hours           text,
  biz_address         text,
  biz_pricing         text,
  plan                text default 'growth',
  status              text default 'trial',
  trial_ends_at       timestamptz,
  vapi_assistant_id   text,
  missedcall_number   text,
  created_at          timestamptz default now()
);

create table if not exists leads (
  id             bigint generated always as identity primary key,
  business_id    uuid references businesses(id),
  call_id        text,
  name           text,
  issue          text,
  phone          text,
  caller_number  text,
  received_at    timestamptz default now()
);

create table if not exists calls (
  id               text primary key,
  business_id      uuid references businesses(id),
  caller_number    text,
  started_at       timestamptz,
  ended_at         timestamptz,
  duration_seconds int,
  status           text,
  recording_url    text,
  created_at       timestamptz default now()
);

create index if not exists businesses_email_idx  on businesses (email);
create index if not exists leads_business_idx    on leads (business_id, received_at desc);
create index if not exists calls_business_idx    on calls (business_id, started_at desc);
