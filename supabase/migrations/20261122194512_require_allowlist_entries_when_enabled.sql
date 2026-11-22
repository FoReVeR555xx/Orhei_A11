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
  select lower(split_part(coalesce(u.email,''),'@',1)) into v_login
  from auth.users u where u.id = p_uid limit 1;

  select coalesce(r.whitelist_enabled,false) into v_whitelist_enabled
  from public.device_access_revision r where r.singleton = true;

  select exists (
    select 1 from public.device_access_rules r
    where r.enabled and (r.user_id is null or r.user_id = p_uid) and r.mode = 'deny'
      and ((r.kind = 'device' and r.value = p_device_id)
        or (r.kind = 'ip' and p_ip_host is not null and r.value = p_ip_host))
  ) into v_denied;

  if v_denied then
    return jsonb_build_object('allowed',false,'reason','IP address or device is denied');
  end if;

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

  if not v_ip_allow_required and not v_device_allow_required then
    return jsonb_build_object('allowed',false,'reason','No IP address or device is in the allowlist');
  end if;

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
