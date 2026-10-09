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
