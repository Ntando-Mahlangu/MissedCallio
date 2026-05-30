create table leads (
  id             bigint generated always as identity primary key,
  call_id        text unique,
  name           text,
  issue          text,
  phone          text,
  caller_number  text,
  received_at    timestamptz default now()
);

create table calls (
  id               text primary key,
  caller_number    text,
  started_at       timestamptz,
  ended_at         timestamptz,
  duration_seconds int,
  status           text,
  default now()
);

create index on leads (received_at desc);
create index on calls (started_at desc);