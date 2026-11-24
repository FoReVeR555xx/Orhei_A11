-- User-level revocation cutoff: catches accounts with no live auth.sessions row at revoke time.
create table if not exists public.revoked_auth_users (
  user_id uuid primary key,
  revoked_before timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.revoked_auth_users enable row level security;
revoke all on public.revoked_auth_users from anon, authenticated;
grant select on public.revoked_auth_users to authenticated;
drop policy if exists revoked_auth_users_read_own on public.revoked_auth_users;
create policy revoked_auth_users_read_own
  on public.revoked_auth_users for select to authenticated
  using (user_id = auth.uid());
do $$ begin
  alter publication supabase_realtime add table public.revoked_auth_users;
exception when duplicate_object then null; when undefined_object then null; end $$;

create or replace function public.admin_revoke_account_sessions(p_user_ids uuid[] default '{}', p_all boolean default false)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_login text;
  v_permissions jsonb;
  v_targets uuid[];
  v_count integer := 0;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  select lower(split_part(coalesce(u.email,''),'@',1))
    into v_login from auth.users u where u.id = v_uid;
  select p.permissions into v_permissions from public.profiles p where p.id = v_uid;
  if coalesce(v_login,'') <> 'admin'
     and not coalesce(v_permissions,'[]'::jsonb) @> '["users.manage"]'::jsonb then
    raise exception 'Недостаточно прав для завершения сессий';
  end if;

  if p_all then
    select coalesce(array_agg(u.id), '{}'::uuid[]) into v_targets
    from auth.users u where u.id <> v_uid;
  else
    if coalesce(array_length(p_user_ids,1),0) = 0 then
      raise exception 'Не выбраны аккаунты';
    end if;
    select coalesce(array_agg(u.id), '{}'::uuid[]) into v_targets
    from auth.users u
    where u.id = any(p_user_ids) and u.id <> v_uid;
  end if;

  if coalesce(array_length(v_targets,1),0) = 0 then
    return 0;
  end if;

  insert into public.revoked_auth_users(user_id,revoked_before,updated_at)
  select target_id, clock_timestamp(), clock_timestamp()
  from unnest(v_targets) as target_id
  on conflict(user_id) do update
    set revoked_before = excluded.revoked_before,
        updated_at = excluded.updated_at;

  insert into public.revoked_auth_sessions(session_id,user_id,revoked_at)
  select s.id,s.user_id,clock_timestamp()
  from auth.sessions s
  where s.user_id = any(v_targets)
  on conflict(session_id) do update
    set revoked_at = excluded.revoked_at,
        user_id = excluded.user_id;

  delete from auth.sessions s where s.user_id = any(v_targets);

  select count(*)::integer into v_count from unnest(v_targets);
  return v_count;
end;
$$;
revoke all on function public.admin_revoke_account_sessions(uuid[],boolean) from public, anon;
grant execute on function public.admin_revoke_account_sessions(uuid[],boolean) to authenticated;

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
  v_iat bigint;
  v_revoked_before timestamptz;
  v_session_id uuid;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;

  begin v_iat := nullif(auth.jwt()->>'iat','')::bigint; exception when others then v_iat := null; end;
  begin v_session_id := nullif(auth.jwt()->>'session_id','')::uuid; exception when others then v_session_id := null; end;

  select revoked_before into v_revoked_before
  from public.revoked_auth_users where user_id = v_uid;

  if v_revoked_before is not null and v_iat is not null
     and to_timestamp(v_iat) <= v_revoked_before then
    raise exception using message = 'SESSION_REVOKED: Session terminated by administrator';
  end if;

  if v_session_id is not null and exists (
    select 1 from public.revoked_auth_sessions r where r.session_id = v_session_id
  ) then
    raise exception using message = 'SESSION_REVOKED: Session terminated by administrator';
  end if;

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
