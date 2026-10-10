-- Route and delivery tracking schema.
-- Idempotent so it can safely initialize Preview databases.
create table if not exists public.routes (
  id uuid primary key default gen_random_uuid(),
  driver_id uuid not null references auth.users(id),
  status text not null default 'planned' check (status in ('planned','active','finished')),
  total_km numeric not null default 0,
  started_at timestamptz,
  finished_at timestamptz,
  created_at timestamptz not null default now()
);
create table if not exists public.deliveries (
  id uuid primary key default gen_random_uuid(),
  driver_id uuid references auth.users(id),
  order_number text not null,
  address text not null,
  status text not null default 'pending' check (status in ('pending','active','delivered','cancelled')),
  created_at timestamptz not null default now(),
  delivered_at timestamptz,
  updated_at timestamptz not null default now(),
  source_order_id text,
  client text not null default '',
  phone text not null default '',
  products text not null default '',
  created_by_name text not null default '',
  source_created_at timestamptz,
  segment_km numeric
);
create table if not exists public.route_deliveries (
  id uuid primary key default gen_random_uuid(),
  route_id uuid not null references public.routes(id) on delete cascade,
  delivery_id uuid not null references public.deliveries(id) on delete cascade,
  position integer not null,
  status text not null default 'pending' check (status in ('pending','delivered')),
  delivered_at timestamptz,
  segment_km numeric,
  cumulative_km numeric,
  created_at timestamptz not null default now(),
  unique (route_id, delivery_id)
);
create table if not exists public.route_locations (
  id bigint generated always as identity primary key,
  route_id uuid not null references public.routes(id) on delete cascade,
  driver_id uuid not null references auth.users(id),
  latitude double precision not null check (latitude between -90 and 90),
  longitude double precision not null check (longitude between -180 and 180),
  accuracy real not null default 0,
  speed real,
  heading real,
  recorded_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index if not exists deliveries_driver_status_idx on public.deliveries(driver_id, status);
create index if not exists route_deliveries_route_position_idx on public.route_deliveries(route_id, position);
create index if not exists route_locations_route_recorded_idx on public.route_locations(route_id, recorded_at);
alter table public.routes enable row level security;
alter table public.deliveries enable row level security;
alter table public.route_deliveries enable row level security;
alter table public.route_locations enable row level security;
grant select, insert, update, delete on public.routes, public.deliveries, public.route_deliveries, public.route_locations to authenticated;
grant usage, select on sequence public.route_locations_id_seq to authenticated;
drop policy if exists "authenticated manage routes" on public.routes;
create policy "authenticated manage routes" on public.routes for all to authenticated using (true) with check (true);
drop policy if exists "authenticated manage deliveries" on public.deliveries;
create policy "authenticated manage deliveries" on public.deliveries for all to authenticated using (true) with check (true);
drop policy if exists "authenticated manage route deliveries" on public.route_deliveries;
create policy "authenticated manage route deliveries" on public.route_deliveries for all to authenticated using (true) with check (true);
drop policy if exists "authenticated manage route locations" on public.route_locations;
create policy "authenticated manage route locations" on public.route_locations for all to authenticated using (true) with check (true);
