-- Prefer Cloudflare's client IP header when available; fall back to X-Forwarded-For.
create or replace function public.check_device_access(p_device_id text, p_browser text default null)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid(); v_headers jsonb; v_ip_text text; v_ip inet; v_ip_host text;
  v_device_id text; v_user_agent text; v_login text; v_denied boolean := false;
  v_ip_allow_required boolean := false; v_device_allow_required boolean := false;
  v_ip_allowed boolean := false; v_device_allowed boolean := false; v_allowed boolean := true;
begin
  if v_uid is null then return jsonb_build_object('allowed',false,'reason','Authentication required'); end if;
  v_headers := coalesce(nullif(current_setting('request.headers',true),''),'{}')::jsonb;
  v_ip_text := split_part(coalesce(v_headers->>'cf-connecting-ip',v_headers->>'x-forwarded-for',''),',',1);
  begin v_ip := nullif(trim(v_ip_text),'')::inet; exception when others then v_ip := null; end;
  if v_ip is not null then v_ip_host := host(v_ip); end if;
  v_device_id := coalesce(nullif(v_headers->>'x-device-id',''),nullif(p_device_id,''));
  v_user_agent := coalesce(v_headers->>'user-agent','');
  select split_part(u.email,'@',1) into v_login from auth.users u where u.id=v_uid limit 1;
  if v_login is null then v_login := ''; end if;
  if v_device_id is null then return jsonb_build_object('allowed',false,'reason','Device identifier is missing','ip',v_ip_host); end if;
  insert into public.device_registry(user_id,login,device_id,ip,browser,user_agent,first_seen_at,last_seen_at)
  values(v_uid,v_login,v_device_id,v_ip,coalesce(p_browser,''),v_user_agent,now(),now())
  on conflict(user_id,device_id) do update set login=excluded.login,ip=excluded.ip,browser=excluded.browser,user_agent=excluded.user_agent,last_seen_at=now();
  if lower(v_login)='admin' then return jsonb_build_object('allowed',true,'ip',v_ip_host,'device_id',v_device_id,'browser',coalesce(p_browser,''),'reason',''); end if;
  select exists(select 1 from public.device_access_rules r where r.enabled and (r.user_id is null or r.user_id=v_uid) and ((r.kind='device' and r.value=v_device_id) or (r.kind='ip' and v_ip_host is not null and r.value=v_ip_host)) and r.mode='deny') into v_denied;
  select exists(select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='ip' and (r.user_id is null or r.user_id=v_uid)) into v_ip_allow_required;
  select exists(select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='device' and (r.user_id is null or r.user_id=v_uid)) into v_device_allow_required;
  if v_ip_allow_required then select exists(select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='ip' and (r.user_id is null or r.user_id=v_uid) and v_ip_host is not null and r.value=v_ip_host) into v_ip_allowed; else v_ip_allowed:=true; end if;
  if v_device_allow_required then select exists(select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='device' and (r.user_id is null or r.user_id=v_uid) and r.value=v_device_id) into v_device_allowed; else v_device_allowed:=true; end if;
  v_allowed:=not v_denied and v_ip_allowed and v_device_allowed;
  return jsonb_build_object('allowed',v_allowed,'ip',v_ip_host,'device_id',v_device_id,'browser',coalesce(p_browser,''),'reason',case when v_denied then 'IP address or device is denied' when not v_ip_allowed then 'IP address is not in the allowlist' when not v_device_allowed then 'Device is not in the allowlist' else '' end);
end;
$$;

create or replace function public.touch_my_account_presence()
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid(); v_seen timestamptz; v_headers jsonb; v_ip_text text; v_ip inet; v_ip_host text; v_device_id text; v_login text;
  v_denied boolean := false; v_ip_allow_required boolean := false; v_device_allow_required boolean := false; v_ip_allowed boolean := false; v_device_allowed boolean := false;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  v_headers := coalesce(nullif(current_setting('request.headers',true),''),'{}')::jsonb;
  v_ip_text := split_part(coalesce(v_headers->>'cf-connecting-ip',v_headers->>'x-forwarded-for',''),',',1);
  begin v_ip := nullif(trim(v_ip_text),'')::inet; exception when others then v_ip := null; end;
  if v_ip is not null then v_ip_host := host(v_ip); end if;
  v_device_id := v_headers->>'x-device-id';
  select split_part(u.email,'@',1) into v_login from auth.users u where u.id=v_uid limit 1;
  if lower(coalesce(v_login,''))<>'admin' then
    select exists(select 1 from public.device_access_rules r where r.enabled and (r.user_id is null or r.user_id=v_uid) and ((r.kind='device' and r.value=v_device_id) or (r.kind='ip' and v_ip_host is not null and r.value=v_ip_host)) and r.mode='deny') into v_denied;
    select exists(select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='ip' and (r.user_id is null or r.user_id=v_uid)) into v_ip_allow_required;
    select exists(select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='device' and (r.user_id is null or r.user_id=v_uid)) into v_device_allow_required;
    if v_ip_allow_required then select exists(select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='ip' and (r.user_id is null or r.user_id=v_uid) and v_ip_host is not null and r.value=v_ip_host) into v_ip_allowed; else v_ip_allowed:=true; end if;
    if v_device_allow_required then select exists(select 1 from public.device_access_rules r where r.enabled and r.mode='allow' and r.kind='device' and (r.user_id is null or r.user_id=v_uid) and r.value=v_device_id) into v_device_allowed; else v_device_allowed:=true; end if;
    if v_denied or not v_ip_allowed or not v_device_allowed then
      raise exception using message=case when v_denied then 'ACCESS_BLOCKED: IP address or device is denied' when not v_ip_allowed then 'ACCESS_BLOCKED: IP address is not in the allowlist' else 'ACCESS_BLOCKED: Device is not in the allowlist' end;
    end if;
  end if;
  insert into public.account_presence(user_id,last_seen_at,is_online) values(v_uid,now(),true)
  on conflict(user_id) do update set last_seen_at=excluded.last_seen_at,is_online=true returning last_seen_at into v_seen;
  return v_seen;
end;
$$;

create or replace function orhei_private.enrich_latest_app_log()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_headers jsonb; v_old_id text; v_new_id text; v_ip text; v_device_id text; v_user_agent text; v_browser text; v_log jsonb;
begin
  v_new_id := new.payload->'logs'->0->>'id';
  if tg_op='UPDATE' then
    v_old_id := old.payload->'logs'->0->>'id';
    if v_new_id is null or v_new_id=v_old_id then return new; end if;
    if jsonb_typeof(old.payload->'logs')='array' and exists(select 1 from jsonb_array_elements(old.payload->'logs') as old_log where old_log->>'id'=v_new_id) then return new; end if;
  elsif v_new_id is null then return new;
  end if;
  v_log := new.payload->'logs'->0;
  if jsonb_typeof(v_log)<>'object' then return new; end if;
  v_headers := coalesce(nullif(current_setting('request.headers',true),''),'{}')::jsonb;
  v_ip := split_part(coalesce(v_headers->>'cf-connecting-ip',v_headers->>'x-forwarded-for',''),',',1);
  v_device_id := v_headers->>'x-device-id';
  v_user_agent := v_headers->>'user-agent';
  v_browser := case when v_user_agent ~* 'Edg/' then 'Microsoft Edge' when v_user_agent ~* 'OPR/' then 'Opera' when v_user_agent ~* 'Firefox/' then 'Mozilla Firefox' when v_user_agent ~* 'Chrome/' then 'Google Chrome' when v_user_agent ~* 'Safari/' then 'Safari' else 'Другой браузер' end;
  v_log := v_log || jsonb_build_object('ip',nullif(trim(v_ip),''),'deviceId',v_device_id,'userAgent',v_user_agent,'browser',coalesce(nullif(v_log->>'browser',''),v_browser));
  new.payload := jsonb_set(new.payload,'{logs,0}',v_log,true);
  return new;
end;
$$;
revoke all on function orhei_private.enrich_latest_app_log() from public, anon, authenticated;
