-- Route archive session status used by route history workflows.
-- Idempotent for Preview databases.
create table if not exists public.route_archive_sessions (
  id uuid primary key default gen_random_uuid(),
  route_id uuid references public.routes(id) on delete set null,
  status text not null default 'archived',
  created_at timestamptz not null default now(),
  payload jsonb not null default '{}'::jsonb
);
alter table public.route_archive_sessions
  add column if not exists status text not null default 'archived';
alter table public.route_archive_sessions enable row level security;
grant select, insert, update, delete on public.route_archive_sessions to authenticated;
drop policy if exists "authenticated manage route archive sessions" on public.route_archive_sessions;
create policy "authenticated manage route archive sessions" on public.route_archive_sessions
  for all to authenticated using (true) with check (true);
