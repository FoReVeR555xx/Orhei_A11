-- Corrective fix: revoke Auth sessions, not only mark them.
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
  select lower(split_part(coalesce(u.email,''),'@',1)) into v_login from auth.users u where u.id = v_uid;
  select p.permissions into v_permissions from public.profiles p where p.id = v_uid;
  if coalesce(v_login,'') <> 'admin' and not coalesce(v_permissions,'[]'::jsonb) @> '["users.manage"]'::jsonb then
    raise exception 'Недостаточно прав для завершения сессий';
  end if;
  if p_all then
    insert into public.revoked_auth_sessions(session_id,user_id,revoked_at)
    select s.id,s.user_id,now() from auth.sessions s where s.user_id <> v_uid
    on conflict(session_id) do update set revoked_at=excluded.revoked_at,user_id=excluded.user_id;
    delete from auth.sessions s where s.user_id <> v_uid;
  else
    if coalesce(array_length(p_user_ids,1),0)=0 then raise exception 'Не выбраны аккаунты'; end if;
    insert into public.revoked_auth_sessions(session_id,user_id,revoked_at)
    select s.id,s.user_id,now() from auth.sessions s where s.user_id=any(p_user_ids) and s.user_id <> v_uid
    on conflict(session_id) do update set revoked_at=excluded.revoked_at,user_id=excluded.user_id;
    delete from auth.sessions s where s.user_id=any(p_user_ids) and s.user_id <> v_uid;
  end if;
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;
revoke all on function public.admin_revoke_account_sessions(uuid[],boolean) from public, anon;
grant execute on function public.admin_revoke_account_sessions(uuid[],boolean) to authenticated;
