-- Force selected account sessions to re-authenticate. The current owner's session is never revoked.
create table if not exists public.revoked_auth_sessions (
  session_id uuid primary key,
  user_id uuid not null,
  revoked_at timestamptz not null default now()
);
create index if not exists revoked_auth_sessions_user_id_idx on public.revoked_auth_sessions(user_id);
alter table public.revoked_auth_sessions enable row level security;
revoke all on public.revoked_auth_sessions from anon, authenticated;
grant select on public.revoked_auth_sessions to authenticated;
drop policy if exists revoked_sessions_read_own on public.revoked_auth_sessions;
create policy revoked_sessions_read_own on public.revoked_auth_sessions for select to authenticated using (user_id = auth.uid());
do $$ begin
  alter publication supabase_realtime add table public.revoked_auth_sessions;
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
  v_count integer := 0;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  select lower(split_part(coalesce(u.email,''),'@',1)) into v_login from auth.users u where u.id=v_uid;
  select p.permissions into v_permissions from public.profiles p where p.id=v_uid;
  if coalesce(v_login,'') <> 'admin' and not coalesce(v_permissions,'[]'::jsonb) @> '["users.manage"]'::jsonb then
    raise exception 'Недостаточно прав для завершения сессий';
  end if;
  if p_all then
    insert into public.revoked_auth_sessions(session_id,user_id,revoked_at)
    select s.id,s.user_id,now()
    from auth.sessions s
    where s.user_id <> v_uid
    on conflict(session_id) do update set revoked_at=excluded.revoked_at,user_id=excluded.user_id;
  else
    if coalesce(array_length(p_user_ids,1),0)=0 then raise exception 'Не выбраны аккаунты'; end if;
    insert into public.revoked_auth_sessions(session_id,user_id,revoked_at)
    select s.id,s.user_id,now()
    from auth.sessions s
    where s.user_id = any(p_user_ids) and s.user_id <> v_uid
    on conflict(session_id) do update set revoked_at=excluded.revoked_at,user_id=excluded.user_id;
  end if;
  get diagnostics v_count = row_count;
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
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  if exists (
    select 1 from public.revoked_auth_sessions r
    where r.session_id = nullif(auth.jwt()->>'session_id','')::uuid
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

create or replace function public.touch_my_account_presence()
returns timestamptz language sql security invoker set search_path = ''
as $$ select orhei_private.touch_my_account_presence_impl(null); $$;
revoke all on function public.touch_my_account_presence() from public, anon;
grant execute on function public.touch_my_account_presence() to authenticated;

create or replace function public.touch_my_account_presence(p_device_id text)
returns timestamptz language sql security invoker set search_path = ''
as $$ select orhei_private.touch_my_account_presence_impl(p_device_id); $$;
revoke all on function public.touch_my_account_presence(text) from public, anon;
grant execute on function public.touch_my_account_presence(text) to authenticated;
