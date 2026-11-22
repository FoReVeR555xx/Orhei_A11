-- Global master switch for the device/IP allowlist.
-- Default OFF preserves normal login for all active accounts; deny rules always apply.
alter table public.device_access_revision
  add column if not exists whitelist_enabled boolean not null default false;

update public.device_access_revision
set whitelist_enabled = coalesce(whitelist_enabled, false)
where singleton = true;

create or replace function orhei_private.evaluate_device_access_policy(
  p_uid uuid,
  p_device_id text,
  p_ip_host text
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_login text := '';
  v_whitelist_enabled boolean := false;
  v_denied boolean := false;
  v_ip_allow_required boolean := false;
  v_device_allow_required boolean := false;
  v_ip_allowed boolean := true;
  v_device_allowed boolean := true;
begin
  select lower(split_part(coalesce(u.email,''),'@',1))
    into v_login
  from auth.users u
  where u.id = p_uid
  limit 1;

  select coalesce(r.whitelist_enabled,false)
    into v_whitelist_enabled
  from public.device_access_revision r
  where r.singleton = true;

  -- Blacklist rules are unconditional and have priority, including for owner.
  select exists (
    select 1
    from public.device_access_rules r
    where r.enabled
      and (r.user_id is null or r.user_id = p_uid)
      and r.mode = 'deny'
      and (
        (r.kind = 'device' and r.value = p_device_id)
        or (r.kind = 'ip' and p_ip_host is not null and r.value = p_ip_host)
      )
  ) into v_denied;

  if v_denied then
    return jsonb_build_object('allowed',false,'reason','IP address or device is denied');
  end if;

  -- When disabled, allow all authenticated accounts except blacklist matches.
  -- The owner account is exempt from allowlist-only mode as a recovery safeguard.
  if not v_whitelist_enabled or v_login = 'admin' then
    return jsonb_build_object('allowed',true,'reason','');
  end if;

  select exists (
    select 1 from public.device_access_rules r
    where r.enabled and r.mode='allow' and r.kind='ip'
      and (r.user_id is null or r.user_id=p_uid)
  ) into v_ip_allow_required;

  select exists (
    select 1 from public.device_access_rules r
    where r.enabled and r.mode='allow' and r.kind='device'
      and (r.user_id is null or r.user_id=p_uid)
  ) into v_device_allow_required;

  if v_ip_allow_required then
    select exists (
      select 1 from public.device_access_rules r
      where r.enabled and r.mode='allow' and r.kind='ip'
        and (r.user_id is null or r.user_id=p_uid)
        and p_ip_host is not null and r.value=p_ip_host
    ) into v_ip_allowed;
  end if;

  if v_device_allow_required then
    select exists (
      select 1 from public.device_access_rules r
      where r.enabled and r.mode='allow' and r.kind='device'
        and (r.user_id is null or r.user_id=p_uid)
        and r.value=p_device_id
    ) into v_device_allowed;
  end if;

  return jsonb_build_object(
    'allowed',v_ip_allowed and v_device_allowed,
    'reason',case
      when not v_ip_allowed then 'IP address is not in the allowlist'
      when not v_device_allowed then 'Device is not in the allowlist'
      else ''
    end
  );
end;
$$;
revoke all on function orhei_private.evaluate_device_access_policy(uuid,text,text) from public, anon, authenticated;

create or replace function orhei_private.set_device_access_whitelist_enabled_impl(p_enabled boolean)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not orhei_private.is_site_owner() then
    raise exception 'Not authorized';
  end if;

  update public.device_access_revision
  set whitelist_enabled = coalesce(p_enabled,false),
      revision = revision + 1,
      updated_at = now()
  where singleton = true;

  return coalesce(p_enabled,false);
end;
$$;
revoke all on function orhei_private.set_device_access_whitelist_enabled_impl(boolean) from public, anon, authenticated;
grant execute on function orhei_private.set_device_access_whitelist_enabled_impl(boolean) to authenticated;

create or replace function public.set_device_access_whitelist_enabled(p_enabled boolean)
returns boolean
language sql
security invoker
set search_path = ''
as $$
  select orhei_private.set_device_access_whitelist_enabled_impl(p_enabled);
$$;
revoke all on function public.set_device_access_whitelist_enabled(boolean) from public, anon;
grant execute on function public.set_device_access_whitelist_enabled(boolean) to authenticated;

create or replace function orhei_private.check_device_access_impl(p_device_id text, p_browser text default null)
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
  v_ip_host text;
  v_device_id text;
  v_user_agent text;
  v_login text;
  v_policy jsonb;
begin
  if v_uid is null then
    return jsonb_build_object('allowed',false,'reason','Authentication required');
  end if;

  v_headers := coalesce(nullif(current_setting('request.headers',true),''),'{}')::jsonb;
  v_ip_text := split_part(coalesce(v_headers->>'cf-connecting-ip',v_headers->>'x-forwarded-for',''),',',1);
  begin
    v_ip := nullif(trim(v_ip_text),'')::inet;
  exception when others then
    v_ip := null;
  end;
  if v_ip is not null then v_ip_host := host(v_ip); end if;

  v_device_id := coalesce(nullif(v_headers->>'x-device-id',''),nullif(p_device_id,''));
  v_user_agent := coalesce(v_headers->>'user-agent','');
  select split_part(u.email,'@',1) into v_login
  from auth.users u where u.id=v_uid limit 1;

  if v_device_id is null then
    return jsonb_build_object('allowed',false,'reason','Device identifier is missing','ip',v_ip_host);
  end if;

  insert into public.device_registry(user_id,login,device_id,ip,browser,user_agent,first_seen_at,last_seen_at)
  values(v_uid,coalesce(v_login,''),v_device_id,v_ip,coalesce(p_browser,''),v_user_agent,now(),now())
  on conflict(user_id,device_id) do update
    set login=excluded.login,ip=excluded.ip,browser=excluded.browser,
        user_agent=excluded.user_agent,last_seen_at=now();

  v_policy := orhei_private.evaluate_device_access_policy(v_uid,v_device_id,v_ip_host);
  return jsonb_build_object(
    'allowed',coalesce((v_policy->>'allowed')::boolean,false),
    'ip',v_ip_host,
    'device_id',v_device_id,
    'browser',coalesce(p_browser,''),
    'reason',coalesce(v_policy->>'reason','')
  );
end;
$$;
revoke all on function orhei_private.check_device_access_impl(text,text) from public, anon;
grant execute on function orhei_private.check_device_access_impl(text,text) to authenticated;

create or replace function public.check_device_access(p_device_id text, p_browser text default null)
returns jsonb
language sql
security invoker
set search_path = ''
as $$
  select orhei_private.check_device_access_impl(p_device_id,p_browser);
$$;
revoke all on function public.check_device_access(text,text) from public, anon;
grant execute on function public.check_device_access(text,text) to authenticated;

create or replace function orhei_private.touch_my_account_presence_impl(p_device_id text default null)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_seen timestamptz;
  v_headers jsonb;
  v_ip_text text;
  v_ip inet;
  v_ip_host text;
  v_device_id text;
  v_policy jsonb;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;

  v_headers := coalesce(nullif(current_setting('request.headers',true),''),'{}')::jsonb;
  v_ip_text := split_part(coalesce(v_headers->>'cf-connecting-ip',v_headers->>'x-forwarded-for',''),',',1);
  begin v_ip := nullif(trim(v_ip_text),'')::inet; exception when others then v_ip := null; end;
  if v_ip is not null then v_ip_host := host(v_ip); end if;
  v_device_id := coalesce(nullif(v_headers->>'x-device-id',''),nullif(p_device_id,''));

  v_policy := orhei_private.evaluate_device_access_policy(v_uid,v_device_id,v_ip_host);
  if not coalesce((v_policy->>'allowed')::boolean,false) then
    raise exception using message = 'ACCESS_BLOCKED: ' || coalesce(v_policy->>'reason','Access denied');
  end if;

  insert into public.account_presence(user_id,last_seen_at,is_online)
  values(v_uid,now(),true)
  on conflict(user_id) do update
    set last_seen_at=excluded.last_seen_at,is_online=true
  returning last_seen_at into v_seen;

  return v_seen;
end;
$$;
revoke all on function orhei_private.touch_my_account_presence_impl(text) from public, anon;
grant execute on function orhei_private.touch_my_account_presence_impl(text) to authenticated;

create or replace function public.touch_my_account_presence()
returns timestamptz
language sql
security invoker
set search_path = ''
as $$ select orhei_private.touch_my_account_presence_impl(null); $$;
revoke all on function public.touch_my_account_presence() from public, anon;
grant execute on function public.touch_my_account_presence() to authenticated;

create or replace function public.touch_my_account_presence(p_device_id text)
returns timestamptz
language sql
security invoker
set search_path = ''
as $$ select orhei_private.touch_my_account_presence_impl(p_device_id); $$;
revoke all on function public.touch_my_account_presence(text) from public, anon;
grant execute on function public.touch_my_account_presence(text) to authenticated;

comment on column public.device_access_revision.whitelist_enabled is
  'Global master switch for IP/device allowlist enforcement; false by default. Deny rules are always enforced.';
