-- Bomba / AV Electronic: central state + user profiles.
-- Run this in Supabase SQL Editor before using the cloud version.
create table if not exists public.app_state (
  id text primary key default 'main',
  payload jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  updated_by uuid references auth.users(id)
);

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  login text unique not null,
  display_name text not null default '',
  group_name text not null default 'Сотрудники',
  status text not null default 'Активен',
  permissions jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.app_state enable row level security;
alter table public.profiles enable row level security;

grant select, insert, update on public.app_state to authenticated;
grant select on public.profiles to authenticated;

drop policy if exists "authenticated can read app state" on public.app_state;
create policy "authenticated can read app state" on public.app_state for select to authenticated using (true);
drop policy if exists "authenticated can insert app state" on public.app_state;
create policy "authenticated can insert app state" on public.app_state for insert to authenticated with check (updated_by = auth.uid());
drop policy if exists "authenticated can update app state" on public.app_state;
create policy "authenticated can update app state" on public.app_state for update to authenticated using (true) with check (updated_by = auth.uid());

drop policy if exists "authenticated can read profiles" on public.profiles;
create policy "authenticated can read profiles" on public.profiles for select to authenticated using (true);

insert into public.app_state(id,payload) values ('main','{}'::jsonb) on conflict (id) do nothing;

-- Automatically create a profile whenever a Supabase Auth user is created.
create or replace function public.handle_new_bomba_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
declare
  v_login text;
begin
  v_login := lower(split_part(coalesce(new.email, ''), '@', 1));
  insert into public.profiles(id, login, display_name, group_name, status, permissions)
  values (
    new.id,
    v_login,
    coalesce(new.raw_user_meta_data->>'display_name', v_login),
    coalesce(new.raw_user_meta_data->>'group_name', 'Сотрудники'),
    'Активен',
    coalesce(new.raw_user_meta_data->'permissions', '[]'::jsonb)
  )
  on conflict (id) do update set
    login = excluded.login,
    display_name = excluded.display_name,
    group_name = excluded.group_name,
    permissions = excluded.permissions,
    updated_at = now();
  return new;
end;
$$;

drop trigger if exists on_bomba_auth_user_created on auth.users;
create trigger on_bomba_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_bomba_user();

-- Allow an authenticated user to create/update only their own profile.
grant insert, update on public.profiles to authenticated;
drop policy if exists "authenticated can insert own profile" on public.profiles;
create policy "authenticated can insert own profile" on public.profiles for insert to authenticated with check (id = auth.uid());
drop policy if exists "authenticated can update own profile" on public.profiles;
create policy "authenticated can update own profile" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
