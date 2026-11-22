create schema if not exists orhei_private;
revoke all on schema orhei_private from public, anon, authenticated;

-- Device/IP access controls. Device identity is a persistent browser-generated ID,
-- not a hardware MAC address (web browsers cannot read a remote MAC address).

create table if not exists public.device_registry (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  login text not null,
  device_id text not null,
  ip inet,
  browser text,
  user_agent text,
  first_seen_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  unique (user_id, device_id)
);

create index if not exists device_registry_last_seen_idx
  on public.device_registry (last_seen_at desc);
create index if not exists device_registry_ip_idx
  on public.device_registry (ip);
create index if not exists device_registry_device_idx
  on public.device_registry (device_id);

create table if not exists public.device_access_rules (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  kind text not null check (kind in ('ip','device')),
  value text not null,
  mode text not null check (mode in ('allow','deny')),
  enabled boolean not null default true,
  note text not null default '',
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  unique (user_id, kind, value, mode)
);

create index if not exists device_access_rules_lookup_idx
  on public.device_access_rules (kind, mode, enabled, user_id, value);

create table if not exists public.device_access_revision (
  singleton boolean primary key default true check (singleton),
  revision bigint not null default 0,
  updated_at timestamptz not null default now()
);
insert into public.device_access_revision(singleton) values (true)
on conflict (singleton) do nothing;

alter table public.device_registry enable row level security;
alter table public.device_access_rules enable row level security;
alter table public.device_access_revision enable row level security;

revoke all on public.device_registry, public.device_access_rules, public.device_access_revision from anon, authenticated;
grant select on public.device_registry, public.device_access_rules, public.device_access_revision to authenticated;
grant insert, update, delete on public.device_access_rules to authenticated;

create policy "site owners can view known devices"
  on public.device_registry for select to authenticated
  using (exists (select 1 from public.profiles p where p.id = (select auth.uid()) and lower(p.login) = 'admin'));

create policy "site owners can manage device access rules"
  on public.device_access_rules for all to authenticated
  using (exists (select 1 from public.profiles p where p.id = (select auth.uid()) and lower(p.login) = 'admin'))
  with check (exists (select 1 from public.profiles p where p.id = (select auth.uid()) and lower(p.login) = 'admin'));

create policy "authenticated can observe access policy revision"
  on public.device_access_revision for select to authenticated
  using (true);

create or replace function public.check_device_access(p_device_id text, p_browser text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_headers jsonb;
  v_ip_text text;
  v_ip inet;
  v_device_id text;
  v_user_agent text;
  v_login text;
  v_denied boolean := false;
  v_ip_allow_required boolean := false;
  v_device_allow_required boolean := false;
  v_ip_allowed boolean := false;
  v_device_allowed boolean := false;
  v_allowed boolean := true;
begin
  if v_uid is null then
    return jsonb_build_object('allowed', false, 'reason', 'Authentication required');
  end if;

  v_headers := coalesce(nullif(current_setting('request.headers', true), ''), '{}')::jsonb;
  v_ip_text := split_part(coalesce(v_headers->>'x-forwarded-for', v_headers->>'cf-connecting-ip', ''), ',', 1);
  begin
    v_ip := nullif(trim(v_ip_text), '')::inet;
  exception when others then
    v_ip := null;
  end;
  v_device_id := coalesce(nullif(v_headers->>'x-device-id',''), nullif(p_device_id,''));
  v_user_agent := coalesce(v_headers->>'user-agent','');

  select p.login into v_login from public.profiles p where p.id = v_uid limit 1;
  if v_login is null then v_login := ''; end if;

  if v_device_id is null then
    return jsonb_build_object('allowed', false, 'reason', 'Device identifier is missing', 'ip', v_ip::text);
  end if;

  insert into public.device_registry(user_id, login, device_id, ip, browser, user_agent, first_seen_at, last_seen_at)
  values (v_uid, v_login, v_device_id, v_ip, coalesce(p_browser,''), v_user_agent, now(), now())
  on conflict (user_id, device_id) do update
    set login = excluded.login,
        ip = excluded.ip,
        browser = excluded.browser,
        user_agent = excluded.user_agent,
        last_seen_at = now();

  select exists (
    select 1 from public.device_access_rules r
    where r.enabled and (r.user_id is null or r.user_id = v_uid)
      and ((r.kind = 'device' and r.value = v_device_id)
        or (r.kind = 'ip' and v_ip is not null and r.value = v_ip::text))
      and r.mode = 'deny'
  ) into v_denied;

  select exists (select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='ip' and (r.user_id is null or r.user_id=v_uid))
    into v_ip_allow_required;
  select exists (select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='device' and (r.user_id is null or r.user_id=v_uid))
    into v_device_allow_required;

  if v_ip_allow_required then
    select exists (select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='ip' and (r.user_id is null or r.user_id=v_uid) and v_ip is not null and r.value=v_ip::text)
      into v_ip_allowed;
  else v_ip_allowed := true; end if;

  if v_device_allow_required then
    select exists (select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='device' and (r.user_id is null or r.user_id=v_uid) and r.value=v_device_id)
      into v_device_allowed;
  else v_device_allowed := true; end if;

  v_allowed := not v_denied and v_ip_allowed and v_device_allowed;
  return jsonb_build_object(
    'allowed', v_allowed,
    'ip', v_ip::text,
    'device_id', v_device_id,
    'browser', coalesce(p_browser,''),
    'reason', case when v_denied then 'IP address or device is denied'
                   when not v_ip_allowed then 'IP address is not in the allowlist'
                   when not v_device_allowed then 'Device is not in the allowlist'
                   else '' end
  );
end;
$$;

revoke all on function public.check_device_access(text,text) from public, anon;
grant execute on function public.check_device_access(text,text) to authenticated;

create or replace function orhei_private.bump_device_access_revision()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.device_access_revision
    set revision = revision + 1, updated_at = now()
    where singleton = true;
  return null;
end;
$$;
revoke all on function orhei_private.bump_device_access_revision() from public, anon, authenticated;

drop trigger if exists device_access_rules_revision on public.device_access_rules;
create trigger device_access_rules_revision
after insert or update or delete on public.device_access_rules
for each statement execute function orhei_private.bump_device_access_revision();

do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname='supabase_realtime' and schemaname='public' and tablename='device_access_revision'
     ) then
    alter publication supabase_realtime add table public.device_access_revision;
  end if;
end $$;


-- Attach the real request IP and browser/device headers to the newest action log
-- inside the same app_state write (no extra Data API request per save).
create or replace function orhei_private.enrich_latest_app_log()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_headers jsonb;
  v_old_id text;
  v_new_id text;
  v_ip text;
  v_device_id text;
  v_user_agent text;
  v_log jsonb;
begin
  v_new_id := new.payload->'logs'->0->>'id';
  if tg_op = 'UPDATE' then
    v_old_id := old.payload->'logs'->0->>'id';
  else
    v_old_id := null;
  end if;
  if v_new_id is null or v_new_id = v_old_id then
    return new;
  end if;
  v_log := new.payload->'logs'->0;
  if jsonb_typeof(v_log) <> 'object' then
    return new;
  end if;
  v_headers := coalesce(nullif(current_setting('request.headers', true), ''), '{}')::jsonb;
  v_ip := split_part(coalesce(v_headers->>'x-forwarded-for', v_headers->>'cf-connecting-ip', ''), ',', 1);
  v_device_id := v_headers->>'x-device-id';
  v_user_agent := v_headers->>'user-agent';
  v_log := v_log || jsonb_build_object('ip', nullif(trim(v_ip), ''), 'deviceId', v_device_id, 'userAgent', v_user_agent);
  new.payload := jsonb_set(new.payload, '{logs,0}', v_log, true);
  return new;
end;
$$;
revoke all on function orhei_private.enrich_latest_app_log() from public, anon, authenticated;
drop trigger if exists app_state_enrich_latest_log on public.app_state;
create trigger app_state_enrich_latest_log
before insert or update on public.app_state
for each row execute function orhei_private.enrich_latest_app_log();

comment on table public.device_registry is 'Known browser/device identifiers and last-seen IP metadata. device_id is not a MAC address.';
comment on table public.device_access_rules is 'Global or per-account allow/deny rules for IP addresses and browser device identifiers.';
