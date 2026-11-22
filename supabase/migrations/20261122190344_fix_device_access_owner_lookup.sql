-- The current application stores accounts in Supabase Auth metadata; public.profiles
-- is empty in this project. Use the immutable Auth email for owner checks.

create or replace function orhei_private.is_site_owner()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from auth.users u
    where u.id = auth.uid() and lower(u.email) = 'admin@bomba.local'
  );
$$;
revoke all on function orhei_private.is_site_owner() from public, anon;
grant usage on schema orhei_private to authenticated;
grant execute on function orhei_private.is_site_owner() to authenticated;

drop policy if exists "site owners can view known devices" on public.device_registry;
create policy "site owners can view known devices"
  on public.device_registry for select to authenticated
  using (orhei_private.is_site_owner());

drop policy if exists "site owners can manage device access rules" on public.device_access_rules;
create policy "site owners can manage device access rules"
  on public.device_access_rules for all to authenticated
  using (orhei_private.is_site_owner())
  with check (orhei_private.is_site_owner());

create index if not exists device_access_rules_created_by_idx
  on public.device_access_rules (created_by);

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

  select split_part(u.email, '@', 1) into v_login from auth.users u where u.id = v_uid limit 1;
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

  -- Keep the owner account accessible so a global rule cannot lock out administration.
  if lower(v_login) = 'admin' then
    return jsonb_build_object('allowed', true, 'ip', v_ip::text, 'device_id', v_device_id,
                              'browser', coalesce(p_browser,''), 'reason', '');
  end if;

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

create or replace function public.get_device_access_accounts()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not orhei_private.is_site_owner() then
    raise exception 'Not authorized';
  end if;
  return coalesce((
    select jsonb_agg(jsonb_build_object(
      'id',u.id,
      'login',split_part(u.email,'@',1),
      'name',coalesce(u.raw_user_meta_data->>'display_name',split_part(u.email,'@',1)),
      'group_name',coalesce(u.raw_user_meta_data->>'group_name','')
    ) order by u.email)
    from auth.users u
  ), '[]'::jsonb);
end;
$$;
revoke all on function public.get_device_access_accounts() from public, anon;
grant execute on function public.get_device_access_accounts() to authenticated;
