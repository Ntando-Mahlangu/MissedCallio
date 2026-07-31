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

create table if not exists appointments (
  id               bigint generated always as identity primary key,
  business_id      uuid references businesses(id) on delete cascade,
  call_id          text,
  name             text not null,
  phone            text not null,
  service          text,
  appointment_time timestamptz not null,
  notes            text,
  status           text default 'confirmed',
  reminder_sent    boolean default false,
  created_at       timestamptz default now()
);

create table if not exists auth_otps (
  id         bigint generated always as identity primary key,
  email      text not null,
  otp        text not null,
  expires_at timestamptz not null,
  used       boolean default false,
  created_at timestamptz default now()
);

create index if not exists auth_otps_lookup_idx      on auth_otps (email, expires_at) where used = false;
create index if not exists businesses_email_idx      on businesses (email);
create index if not exists leads_business_idx        on leads (business_id, received_at desc);
create index if not exists calls_business_idx        on calls (business_id, started_at desc);
create index if not exists appointments_business_idx on appointments (business_id, appointment_time desc);
create index if not exists appointments_reminder_idx on appointments (appointment_time, reminder_sent) where reminder_sent = false;
create index if not exists leads_phone_idx           on leads (business_id, phone);
create index if not exists appointments_phone_idx    on appointments (business_id, phone);

-- Staff directory
create table if not exists staff (
  id           bigint generated always as identity primary key,
  business_id  uuid references businesses(id) on delete cascade,
  name         text not null,
  role         text,
  phone        text,
  email        text,
  active       boolean default true,
  created_at   timestamptz default now()
);
create index if not exists staff_business_idx on staff (business_id);

-- Slack notifications
alter table businesses add column if not exists slack_webhook_url text;

-- Voicemail email
alter table businesses add column if not exists voicemail_email text;

-- On-hold message
alter table businesses add column if not exists hold_message text;

-- Paddle billing
alter table businesses
  add column if not exists paddle_subscription_id text,
  add column if not exists paddle_customer_id     text,
  add column if not exists last_payment_at        timestamptz,
  add column if not exists cancelled_at           timestamptz;

-- Small-office / team support
alter table businesses
  add column if not exists departments  text,
  add column if not exists team_size    text,
  add column if not exists office_type  text;

-- Team members (dashboard access + SMS routing)
create table if not exists team_members (
  id           bigint generated always as identity primary key,
  business_id  uuid references businesses(id) on delete cascade,
  name         text,
  role         text default 'member',
  phone        text,
  email        text not null,
  notify_sms   boolean default true,
  created_at   timestamptz default now(),
  unique(email)
);
create index if not exists team_members_email_idx on team_members (email);
create index if not exists team_members_biz_idx   on team_members (business_id);

create or replace function count_returning_callers(biz_id uuid)
returns bigint language sql stable as $$
  select count(*) from (
    select phone from leads
    where business_id = biz_id and phone is not null
    group by phone having count(*) > 1
  ) sub;
$$;
