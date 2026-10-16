-- Idempotency ledger: one email per internal notification and recipient.
create table if not exists public.email_notification_sent (
  notification_id text not null,
  recipient_login text not null,
  recipient_email text not null,
  sent_at timestamptz not null default now(),
  primary key (notification_id, recipient_login)
);
alter table public.email_notification_sent enable row level security;
revoke all on public.email_notification_sent from anon, authenticated;
grant all on public.email_notification_sent to service_role;
