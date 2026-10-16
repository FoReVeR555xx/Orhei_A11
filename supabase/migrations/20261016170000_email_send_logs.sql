-- Email delivery audit log; only owner-group profiles can read it.
create table if not exists public.email_send_logs (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  recipient_login text,
  recipient_email text,
  email_type text not null default 'notification',
  subject text,
  body text,
  status text not null check (status in ('attempt','sent','failed')),
  error_message text
);
create index if not exists email_send_logs_created_at_idx on public.email_send_logs(created_at desc);
alter table public.email_send_logs enable row level security;
revoke all on public.email_send_logs from anon, authenticated;
grant select on public.email_send_logs to authenticated;
grant all on public.email_send_logs to service_role;
drop policy if exists "site owners can read email send logs" on public.email_send_logs;
create policy "site owners can read email send logs" on public.email_send_logs for select to authenticated
using (exists (select 1 from public.profiles p where p.id = auth.uid() and lower(p.group_name) = lower('Владельцы')));
-- Keep the last 48 hours only. Also run cleanup on each log insert.
create or replace function public.cleanup_email_send_logs()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  delete from public.email_send_logs where created_at < now() - interval '48 hours';
  return new;
end; $$;
drop trigger if exists email_send_logs_cleanup on public.email_send_logs;
create trigger email_send_logs_cleanup after insert on public.email_send_logs for each row execute function public.cleanup_email_send_logs();
