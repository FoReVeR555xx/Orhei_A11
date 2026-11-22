-- Reuse the app's existing 45-second presence heartbeat to re-check IP/device
-- rules for active sessions. This adds no new client request or polling timer.
create or replace function public.touch_my_account_presence()
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
  v_login text;
  v_denied boolean := false;
  v_ip_allow_required boolean := false;
  v_device_allow_required boolean := false;
  v_ip_allowed boolean := false;
  v_device_allowed boolean := false;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;

  v_headers := coalesce(nullif(current_setting('request.headers', true), ''), '{}')::jsonb;
  v_ip_text := split_part(coalesce(v_headers->>'x-forwarded-for', v_headers->>'cf-connecting-ip', ''), ',', 1);
  begin v_ip := nullif(trim(v_ip_text), '')::inet; exception when others then v_ip := null; end;
  if v_ip is not null then v_ip_host := host(v_ip); end if;
  v_device_id := v_headers->>'x-device-id';
  select split_part(u.email, '@', 1) into v_login from auth.users u where u.id=v_uid limit 1;

  if lower(coalesce(v_login,'')) <> 'admin' then
    select exists (select 1 from public.device_access_rules r where r.enabled and (r.user_id is null or r.user_id=v_uid)
      and ((r.kind='device' and r.value=v_device_id) or (r.kind='ip' and v_ip_host is not null and r.value=v_ip_host)) and r.mode='deny') into v_denied;
    select exists (select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='ip' and (r.user_id is null or r.user_id=v_uid)) into v_ip_allow_required;
    select exists (select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='device' and (r.user_id is null or r.user_id=v_uid)) into v_device_allow_required;
    if v_ip_allow_required then
      select exists (select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='ip' and (r.user_id is null or r.user_id=v_uid) and v_ip_host is not null and r.value=v_ip_host) into v_ip_allowed;
    else v_ip_allowed := true; end if;
    if v_device_allow_required then
      select exists (select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='device' and (r.user_id is null or r.user_id=v_uid) and r.value=v_device_id) into v_device_allowed;
    else v_device_allowed := true; end if;
    if v_denied or not v_ip_allowed or not v_device_allowed then
      raise exception using message = case when v_denied then 'ACCESS_BLOCKED: IP address or device is denied'
        when not v_ip_allowed then 'ACCESS_BLOCKED: IP address is not in the allowlist'
        else 'ACCESS_BLOCKED: Device is not in the allowlist' end;
    end if;
  end if;

  insert into public.account_presence(user_id,last_seen_at,is_online) values (v_uid,now(),true)
  on conflict (user_id) do update set last_seen_at=excluded.last_seen_at,is_online=true
  returning last_seen_at into v_seen;
  return v_seen;
end;
$$;
