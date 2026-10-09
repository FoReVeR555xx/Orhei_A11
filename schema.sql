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
  role text not null default 'user' check (role in ('user','admin')),
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

-- Profile changes are performed only by the trusted Edge Function using the service role.
-- Do NOT grant INSERT/UPDATE on profiles to browser clients: otherwise a user could
-- try to change their own permissions/group/status directly through PostgREST.
drop policy if exists "authenticated can insert own profile" on public.profiles;
drop policy if exists "authenticated can update own profile" on public.profiles;

-- Migration for an already existing database.
alter table public.profiles add column if not exists role text not null default 'user';
drop constraint if exists profiles_role_check on public.profiles;
alter table public.profiles add constraint profiles_role_check check (role in ('user','admin'));
update public.profiles set role = 'admin' where lower(login) = 'admin';


-- Normalized service and delivery tables; kept here for new project setup.
-- Normalize services and deliveries out of app_state.payload.
-- Safe to run more than once: existing rows are preserved via ON CONFLICT DO NOTHING.
create table if not exists public.orders (
  id text primary key,
  order_number text,
  status text not null default 'Ожидает',
  created_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  payload jsonb not null default '{}'::jsonb
);
alter table public.orders add column if not exists status text not null default 'Ожидает';
alter table public.orders add column if not exists order_number text;
alter table public.orders add column if not exists created_by text;
alter table public.orders add column if not exists created_at timestamptz not null default now();
alter table public.orders add column if not exists updated_at timestamptz not null default now();
alter table public.orders add column if not exists payload jsonb not null default '{}'::jsonb;

create table if not exists public.services (
  id text primary key,
  service_number text,
  created_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  payload jsonb not null default '{}'::jsonb
);
alter table public.services add column if not exists service_number text;
alter table public.services add column if not exists created_by text;
alter table public.services add column if not exists created_at timestamptz not null default now();
alter table public.services add column if not exists updated_at timestamptz not null default now();
alter table public.services add column if not exists payload jsonb not null default '{}'::jsonb;

create index if not exists orders_status_idx on public.orders(status);
create index if not exists orders_created_at_idx on public.orders(created_at desc);
create index if not exists services_created_at_idx on public.services(created_at desc);

alter table public.orders enable row level security;
alter table public.services enable row level security;
grant select, insert, update, delete on public.orders, public.services to authenticated;

drop policy if exists "authenticated users can read orders" on public.orders;
create policy "authenticated users can read orders" on public.orders for select to authenticated using (true);
drop policy if exists "authenticated users can insert orders" on public.orders;
create policy "authenticated users can insert orders" on public.orders for insert to authenticated with check (true);
drop policy if exists "authenticated users can update orders" on public.orders;
create policy "authenticated users can update orders" on public.orders for update to authenticated using (true) with check (true);
drop policy if exists "authenticated users can delete orders" on public.orders;
create policy "authenticated users can delete orders" on public.orders for delete to authenticated using (true);

drop policy if exists "authenticated users can read services" on public.services;
create policy "authenticated users can read services" on public.services for select to authenticated using (true);
drop policy if exists "authenticated users can insert services" on public.services;
create policy "authenticated users can insert services" on public.services for insert to authenticated with check (true);
drop policy if exists "authenticated users can update services" on public.services;
create policy "authenticated users can update services" on public.services for update to authenticated using (true) with check (true);
drop policy if exists "authenticated users can delete services" on public.services;
create policy "authenticated users can delete services" on public.services for delete to authenticated using (true);

-- Backfill only missing IDs. Existing normalized rows/statuses are never overwritten.
insert into public.orders (id, order_number, status, created_by, created_at, updated_at, payload)
select
  item->>'id',
  coalesce(nullif(item->>'number',''), nullif(item->>'requestNo',''), item->>'id'),
  coalesce(nullif(item->>'status',''), 'Ожидает'),
  nullif(item->>'createdBy',''),
  case
    when coalesce(item->>'createdAt','') ~ '^[0-9]+$'
      then to_timestamp((item->>'createdAt')::double precision / 1000.0)
    else now()
  end,
  now(),
  case when nullif(item->>'status','') is null
    then item || jsonb_build_object('status','Ожидает')
    else item
  end
from public.app_state a
cross join lateral jsonb_array_elements(coalesce(a.payload->'deliveries','[]'::jsonb)) as src(item)
where a.id='main' and nullif(item->>'id','') is not null
on conflict (id) do nothing;

insert into public.services (id, service_number, created_by, created_at, updated_at, payload)
select
  item->>'id',
  coalesce(nullif(item->>'number',''), item->>'id'),
  nullif(item->>'createdBy',''),
  case
    when coalesce(item->>'createdAt','') ~ '^[0-9]+$'
      then to_timestamp((item->>'createdAt')::double precision / 1000.0)
    else now()
  end,
  now(),
  item
from public.app_state a
cross join lateral jsonb_array_elements(coalesce(a.payload->'services','[]'::jsonb)) as src(item)
where a.id='main' and nullif(item->>'id','') is not null
on conflict (id) do nothing;
