-- Bomba A11: idempotent server-side snapshot queue with revision checks.
-- Safe to apply once. This migration does not modify existing rows.

create table if not exists public.sync_state_revision (
  id smallint primary key default 1 check (id = 1),
  revision bigint not null default 0,
  updated_at timestamptz not null default now()
);
insert into public.sync_state_revision(id, revision)
values (1, case when exists (select 1 from public.app_state where id = 'main')
                  or exists (select 1 from public.services)
                  or exists (select 1 from public.orders) then 1 else 0 end)
on conflict (id) do nothing;

alter table public.sync_state_revision enable row level security;
revoke all on public.sync_state_revision from public, anon, authenticated;

create table if not exists public.sync_operations (
  id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  action text not null default 'Изменение данных',
  summary text not null default '',
  status text not null default 'queued' check (status in ('queued','committed','conflict')),
  expected_revision bigint not null,
  resulting_revision bigint,
  error_message text,
  created_at timestamptz not null default now(),
  processed_at timestamptz
);
create index if not exists sync_operations_created_at_idx
  on public.sync_operations(created_at desc);
create index if not exists sync_operations_user_created_idx
  on public.sync_operations(user_id, created_at desc);

alter table public.sync_operations enable row level security;
revoke all on public.sync_operations from anon, authenticated;
grant select on public.sync_operations to authenticated;
drop policy if exists sync_operations_read_own_or_owner on public.sync_operations;
create policy sync_operations_read_own_or_owner
  on public.sync_operations
  for select to authenticated
  using (
    user_id = (select auth.uid())
    or exists (
      select 1 from public.profiles p
      where p.id = (select auth.uid())
        and lower(coalesce(p.group_name, '')) in ('владельцы','владелец','owner','owners')
    )
  );

create or replace function public.bump_sync_state_revision()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if current_setting('bomba.sync_internal', true) = 'on' then
    return coalesce(new, old);
  end if;
  update public.sync_state_revision
     set revision = revision + 1, updated_at = now()
   where id = 1;
  return coalesce(new, old);
end;
$$;
revoke all on function public.bump_sync_state_revision() from public, anon, authenticated;

drop trigger if exists trg_app_state_sync_revision on public.app_state;
create trigger trg_app_state_sync_revision
after insert or update or delete on public.app_state
for each row execute function public.bump_sync_state_revision();

drop trigger if exists trg_orders_sync_revision on public.orders;
create trigger trg_orders_sync_revision
after insert or update or delete on public.orders
for each row execute function public.bump_sync_state_revision();

drop trigger if exists trg_services_sync_revision on public.services;
create trigger trg_services_sync_revision
after insert or update or delete on public.services
for each row execute function public.bump_sync_state_revision();

create or replace function public.get_sync_revision()
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare v_revision bigint;
begin
  if auth.uid() is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  select revision into v_revision from public.sync_state_revision where id = 1;
  return coalesce(v_revision, 0);
end;
$$;
revoke all on function public.get_sync_revision() from public, anon;
grant execute on function public.get_sync_revision() to authenticated;

create or replace function public.submit_sync_snapshot(
  p_operation_id uuid,
  p_expected_revision bigint,
  p_snapshot jsonb,
  p_action text default 'Изменение данных',
  p_summary text default ''
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_user_id uuid := auth.uid();
  v_current_revision bigint;
  v_existing public.sync_operations%rowtype;
  v_operation public.sync_operations%rowtype;
  v_item jsonb;
  v_now timestamptz := now();
  v_new_revision bigint;
  v_service_count integer := 0;
  v_order_count integer := 0;
begin
  if v_user_id is null then
    raise exception 'Authentication required' using errcode = '28000';
  end if;
  if p_operation_id is null then
    raise exception 'Operation ID is required' using errcode = '22023';
  end if;
  if p_snapshot is null or jsonb_typeof(p_snapshot) <> 'object'
     or jsonb_typeof(p_snapshot->'app_state') is distinct from 'object'
     or jsonb_typeof(p_snapshot->'services') is distinct from 'array'
     or jsonb_typeof(p_snapshot->'orders') is distinct from 'array' then
    raise exception 'Invalid snapshot format' using errcode = '22023';
  end if;
  if octet_length(p_snapshot::text) > 12582912 then
    raise exception 'Snapshot exceeds 12 MB limit' using errcode = '22001';
  end if;

  -- Idempotency: a retry with the same ID returns the original outcome.
  select * into v_existing from public.sync_operations where id = p_operation_id;
  if found then
    if v_existing.user_id <> v_user_id then
      raise exception 'Operation ID already belongs to another user' using errcode = '42501';
    end if;
    if v_existing.status = 'committed' then
      return jsonb_build_object('status','already_committed','revision',v_existing.resulting_revision,'current_revision',v_existing.resulting_revision);
    end if;
    if v_existing.status = 'conflict' then
      select revision into v_current_revision from public.sync_state_revision where id = 1;
      return jsonb_build_object('status','conflict','revision',v_existing.resulting_revision,'current_revision',coalesce(v_current_revision,0),'message',coalesce(v_existing.error_message,'Revision conflict'));
    end if;
  else
    insert into public.sync_operations(id,user_id,action,summary,status,expected_revision)
    values (p_operation_id,v_user_id,left(coalesce(p_action,'Изменение данных'),160),left(coalesce(p_summary,''),1200),'queued',coalesce(p_expected_revision,0));
  end if;

  -- Serialize all writes to the shared state, then reject stale snapshots.
  select revision into v_current_revision
    from public.sync_state_revision where id = 1 for update;
  v_current_revision := coalesce(v_current_revision,0);
  if coalesce(p_expected_revision,0) <> v_current_revision then
    update public.sync_operations
       set status = 'conflict', resulting_revision = v_current_revision,
           error_message = format('Revision conflict: expected %s, server has %s',coalesce(p_expected_revision,0),v_current_revision),
           processed_at = now()
     where id = p_operation_id and user_id = v_user_id;
    return jsonb_build_object('status','conflict','revision',v_current_revision,'current_revision',v_current_revision,
      'message',format('Revision conflict: expected %s, server has %s',coalesce(p_expected_revision,0),v_current_revision));
  end if;

  perform set_config('bomba.sync_internal','on',true);

  insert into public.app_state(id,payload,updated_at,updated_by)
  values ('main',p_snapshot->'app_state',v_now,v_user_id)
  on conflict (id) do update
    set payload = excluded.payload, updated_at = excluded.updated_at, updated_by = excluded.updated_by;

  for v_item in select value from jsonb_array_elements(p_snapshot->'services') loop
    if nullif(v_item->>'id','') is null then
      raise exception 'Service row is missing an ID' using errcode = '22023';
    end if;
    insert into public.services(id,service_number,created_by,created_at,updated_at,payload)
    values (
      v_item->>'id', coalesce(v_item->>'service_number',v_item->>'id'), nullif(v_item->>'created_by',''),
      coalesce(nullif(v_item->>'created_at','')::timestamptz,v_now), v_now, coalesce(v_item->'payload','{}'::jsonb)
    )
    on conflict (id) do update set
      service_number=excluded.service_number, created_by=excluded.created_by,
      created_at=excluded.created_at, updated_at=case when public.services.payload is distinct from excluded.payload then v_now else public.services.updated_at end,
      payload=excluded.payload
    where public.services.payload is distinct from excluded.payload
       or public.services.service_number is distinct from excluded.service_number
       or public.services.created_by is distinct from excluded.created_by;
    v_service_count := v_service_count + 1;
  end loop;

  -- Intentionally do not delete rows absent from a snapshot. A snapshot may be
  -- incomplete or originate from an offline client; absence is not a delete request.
  -- Explicit deletions need tombstones / per-record delete operations.

  for v_item in select value from jsonb_array_elements(p_snapshot->'orders') loop
    if nullif(v_item->>'id','') is null then
      raise exception 'Order row is missing an ID' using errcode = '22023';
    end if;
    insert into public.orders(id,order_number,status,created_by,created_at,updated_at,payload)
    values (
      v_item->>'id', coalesce(v_item->>'order_number',v_item->>'id'), coalesce(v_item->>'status','Ожидает'),
      nullif(v_item->>'created_by',''), coalesce(nullif(v_item->>'created_at','')::timestamptz,v_now), v_now,
      coalesce(v_item->'payload','{}'::jsonb)
    )
    on conflict (id) do update set
      order_number=excluded.order_number, status=excluded.status, created_by=excluded.created_by,
      created_at=excluded.created_at, updated_at=case when public.orders.payload is distinct from excluded.payload or public.orders.status is distinct from excluded.status then v_now else public.orders.updated_at end,
      payload=excluded.payload
    where public.orders.payload is distinct from excluded.payload
       or public.orders.status is distinct from excluded.status
       or public.orders.order_number is distinct from excluded.order_number
       or public.orders.created_by is distinct from excluded.created_by;
    v_order_count := v_order_count + 1;
  end loop;

  -- Intentionally do not delete rows absent from a snapshot. A snapshot may be
  -- incomplete or originate from an offline client; absence is not a delete request.
  -- Explicit deletions need tombstones / per-record delete operations.

  update public.sync_state_revision
     set revision = revision + 1, updated_at = now()
   where id = 1
   returning revision into v_new_revision;

  update public.sync_operations
     set status='committed', resulting_revision=v_new_revision, error_message=null, processed_at=now()
   where id=p_operation_id and user_id=v_user_id;

  return jsonb_build_object('status','committed','revision',v_new_revision,'current_revision',v_new_revision,
    'services_processed',v_service_count,'orders_processed',v_order_count);
end;
$$;
revoke all on function public.submit_sync_snapshot(uuid,bigint,jsonb,text,text) from public, anon;
grant execute on function public.submit_sync_snapshot(uuid,bigint,jsonb,text,text) to authenticated;
