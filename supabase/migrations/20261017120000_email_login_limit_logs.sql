-- Track scheduled and suppressed email events, including the related notification.
alter table public.email_send_logs drop constraint if exists email_send_logs_status_check;
alter table public.email_send_logs add constraint email_send_logs_status_check check (status in ('attempt','sent','failed','scheduled','skipped'));
alter table public.email_send_logs add column if not exists notification_id text;
create index if not exists email_send_logs_recipient_status_created_idx on public.email_send_logs(recipient_login, status, created_at desc);
create index if not exists email_send_logs_notification_status_idx on public.email_send_logs(recipient_login, notification_id, status);

-- Persistent ledger is separate from the 48-hour UI log, so the 3-email limit remains accurate.
create table if not exists public.email_delivery_events (
  id bigint generated always as identity primary key,
  recipient_login text not null,
  recipient_email text not null,
  sent_at timestamptz not null default now(),
  email_type text not null default 'digest'
);
create index if not exists email_delivery_events_recipient_sent_at_idx on public.email_delivery_events(recipient_login, sent_at desc);
alter table public.email_delivery_events enable row level security;
revoke all on public.email_delivery_events from anon, authenticated;
grant all on public.email_delivery_events to service_role;
