-- Enrich only genuinely new log rows, not an older row that becomes first after
-- a date-range deletion or a list reorder. Derive browser label from request UA.
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
  v_browser text;
  v_log jsonb;
begin
  v_new_id := new.payload->'logs'->0->>'id';
  if tg_op = 'UPDATE' then
    v_old_id := old.payload->'logs'->0->>'id';
    if v_new_id is null or v_new_id = v_old_id then return new; end if;
    if jsonb_typeof(old.payload->'logs') = 'array' and exists (
      select 1 from jsonb_array_elements(old.payload->'logs') as old_log
      where old_log->>'id' = v_new_id
    ) then return new; end if;
  elsif v_new_id is null then
    return new;
  end if;

  v_log := new.payload->'logs'->0;
  if jsonb_typeof(v_log) <> 'object' then return new; end if;
  v_headers := coalesce(nullif(current_setting('request.headers', true), ''), '{}')::jsonb;
  v_ip := split_part(coalesce(v_headers->>'x-forwarded-for', v_headers->>'cf-connecting-ip', ''), ',', 1);
  v_device_id := v_headers->>'x-device-id';
  v_user_agent := v_headers->>'user-agent';
  v_browser := case
    when v_user_agent ~* 'Edg/' then 'Microsoft Edge'
    when v_user_agent ~* 'OPR/' then 'Opera'
    when v_user_agent ~* 'Firefox/' then 'Mozilla Firefox'
    when v_user_agent ~* 'Chrome/' then 'Google Chrome'
    when v_user_agent ~* 'Safari/' then 'Safari'
    else 'Другой браузер'
  end;
  v_log := v_log || jsonb_build_object(
    'ip', nullif(trim(v_ip), ''),
    'deviceId', v_device_id,
    'userAgent', v_user_agent,
    'browser', coalesce(nullif(v_log->>'browser',''), v_browser)
  );
  new.payload := jsonb_set(new.payload, '{logs,0}', v_log, true);
  return new;
end;
$$;
revoke all on function orhei_private.enrich_latest_app_log() from public, anon, authenticated;
