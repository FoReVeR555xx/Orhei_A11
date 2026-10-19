alter table public.account_presence add column if not exists is_online boolean not null default false;
create or replace function public.touch_my_account_presence()
returns timestamptz language plpgsql security definer set search_path = public, auth, pg_catalog as $$
declare v_uid uuid := auth.uid(); v_seen timestamptz;
begin
  if v_uid is null then raise exception 'Authentication required'; end if;
  insert into public.account_presence(user_id,last_seen_at,is_online) values (v_uid,now(),true)
  on conflict (user_id) do update set last_seen_at=excluded.last_seen_at,is_online=true returning last_seen_at into v_seen;
  return v_seen;
end; $$;
revoke all on function public.touch_my_account_presence() from public, anon;
grant execute on function public.touch_my_account_presence() to authenticated;
create or replace function public.mark_my_account_offline()
returns void language plpgsql security definer set search_path = public, auth, pg_catalog as $$
begin
  if auth.uid() is null then raise exception 'Authentication required'; end if;
  update public.account_presence set is_online=false,last_seen_at=now() where user_id=auth.uid();
end; $$;
revoke all on function public.mark_my_account_offline() from public, anon;
grant execute on function public.mark_my_account_offline() to authenticated;
create or replace function public.get_account_presence()
returns jsonb language sql security definer set search_path = public, auth, pg_catalog as $$
  select coalesce(jsonb_agg(jsonb_build_object('id',p.id,'login',p.login,'display_name',coalesce(nullif(p.display_name,''),p.login),'group_name',p.group_name,'status',p.status,'last_seen_at',ap.last_seen_at,'online',coalesce(ap.is_online and ap.last_seen_at > now() - interval '2 minutes',false)) order by lower(coalesce(nullif(p.display_name,''),p.login))), '[]'::jsonb)
  from public.profiles p left join public.account_presence ap on ap.user_id=p.id where auth.uid() is not null;
$$;
revoke all on function public.get_account_presence() from public, anon;
grant execute on function public.get_account_presence() to authenticated;
