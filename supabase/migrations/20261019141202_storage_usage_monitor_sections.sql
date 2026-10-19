-- Cached Supabase usage monitor. The scheduled job refreshes the snapshot every 5 minutes.
create table if not exists public.bomba_storage_usage_cache (
  id integer primary key default 1 check (id = 1),
  payload jsonb not null default '{}'::jsonb,
  refreshed_at timestamptz not null default now()
);

revoke all on public.bomba_storage_usage_cache from public, anon, authenticated;

create or replace function public.refresh_bomba_storage_usage()
returns void
language plpgsql
security definer
set search_path = public, storage, pg_catalog
as $$
declare
  v_db_bytes bigint;
  v_storage_bytes bigint;
  v_sections jsonb;
  v_buckets jsonb;
  v_folders jsonb;
  v_payload jsonb;
begin
  v_db_bytes := pg_database_size(current_database())::bigint;
  select coalesce(sum(case when coalesce(o.metadata->>'size','') ~ '^[0-9]+$' then (o.metadata->>'size')::bigint else 0::bigint end),0)::bigint
    into v_storage_bytes from storage.objects o;

  -- Approximate breakdown of the app's actual storage layout.
  -- Most app modules are JSON fields in app_state; service documents and product orders
  -- are normalized in their own tables. Service Acts and their archive are nested in siteSettings.
  select coalesce(jsonb_agg(jsonb_build_object('section', section_name, 'bytes', bytes) order by bytes desc), '[]'::jsonb)
    into v_sections
  from (
    select section_name, sum(bytes)::bigint bytes
    from (
      select case e.key
        when 'sales' then 'Продажи'
        when 'salesArchive' then 'Архив продаж'
        when 'walletRows' then 'Кошелёк'
        when 'walletLastUpdated' then 'Кошелёк — служебные данные'
        when 'walletArchive' then 'Архив кошелька'
        when 'deliveryCategories' then 'Категории доставок'
        when 'reportBindings' then 'Привязка / отчёты'
        when 'logs' then 'Логи'
        when 'groups' then 'Группы'
        when 'permissions' then 'Права доступа'
        when 'eventSettings' then 'Мероприятия'
        when 'announcements' then 'Объявления'
        when 'tabOrders' then 'Порядок вкладок'
        else 'Прочие данные приложения'
      end section_name, pg_column_size(e.value)::bigint bytes
      from public.app_state a cross join lateral jsonb_each(coalesce(a.payload, '{}'::jsonb)) e
      where a.id = 'main' and e.key <> 'siteSettings'
      union all
      select case e.key
        when 'serviceActs' then 'Сервис-Акты — текущие'
        when 'serviceActArchive' then 'Сервис-Акты — архив'
        when 'productOrders' then 'Заказы товара — настройки и данные'
        when 'emailNotifications' then 'Настройки почтовых уведомлений'
        when 'autoWriteoffRecipients' then 'Настройки Авто-Списания'
        when 'deliveryReportColumns' then 'Настройки отчётов доставок'
        when 'productOrderCategories' then 'Категории заказов товара'
        when 'deliveryCleanupStatuses' then 'Настройки очистки доставок'
        when 'productOrderCleanupStatuses' then 'Настройки очистки заказов товара'
        when 'serviceCleanupStatuses' then 'Настройки очистки сервисов'
        else 'Настройки сайта — прочее'
      end section_name, pg_column_size(e.value)::bigint bytes
      from public.app_state a cross join lateral jsonb_each(coalesce(a.payload->'siteSettings', '{}'::jsonb)) e
      where a.id = 'main'
      union all
      select 'Документы сервиса', coalesce(sum(pg_column_size(payload)),0)::bigint from public.services
      union all
      select 'Заказы товара / доставки', coalesce(sum(pg_column_size(payload)),0)::bigint from public.orders
      union all
      select 'Профили пользователей', coalesce(sum(pg_column_size(to_jsonb(p))),0)::bigint from public.profiles p
    ) parts
    group by section_name
  ) section_data;

  select coalesce(jsonb_agg(jsonb_build_object('bucket', bucket_id, 'bytes', bytes) order by bytes desc), '[]'::jsonb)
    into v_buckets
  from (
    select o.bucket_id, sum(case when coalesce(o.metadata->>'size','') ~ '^[0-9]+$' then (o.metadata->>'size')::bigint else 0::bigint end)::bigint bytes
    from storage.objects o group by o.bucket_id
  ) b;

  select coalesce(jsonb_agg(jsonb_build_object('folder', folder, 'bytes', bytes) order by bytes desc), '[]'::jsonb)
    into v_folders
  from (
    select o.bucket_id || ' / ' || coalesce(nullif(split_part(o.name, '/', 1), ''), '(корень)') folder,
      sum(case when coalesce(o.metadata->>'size','') ~ '^[0-9]+$' then (o.metadata->>'size')::bigint else 0::bigint end)::bigint bytes
    from storage.objects o group by o.bucket_id, coalesce(nullif(split_part(o.name, '/', 1), ''), '(корень)')
  ) f;

  v_payload := jsonb_build_object(
    'database_bytes', v_db_bytes,
    'storage_bytes', v_storage_bytes,
    'sections', v_sections,
    'buckets', v_buckets,
    'folders', v_folders,
    'measured_at', now(),
    'next_refresh_at', now() + interval '5 minutes'
  );
  insert into public.bomba_storage_usage_cache(id, payload, refreshed_at) values (1, v_payload, now())
    on conflict (id) do update set payload = excluded.payload, refreshed_at = excluded.refreshed_at;
end;
$$;

revoke all on function public.refresh_bomba_storage_usage() from public, anon, authenticated;
grant execute on function public.refresh_bomba_storage_usage() to service_role;

drop function if exists public.get_bomba_storage_usage();
create function public.get_bomba_storage_usage()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare v jsonb;
begin
  select payload into v from public.bomba_storage_usage_cache where id = 1;
  if v is null then
    perform public.refresh_bomba_storage_usage();
    select payload into v from public.bomba_storage_usage_cache where id = 1;
  end if;
  return v;
end;
$$;
revoke all on function public.get_bomba_storage_usage() from public, anon, authenticated;
grant execute on function public.get_bomba_storage_usage() to service_role;

-- pg_cron is available on Supabase projects where the Cron extension is enabled.
create extension if not exists pg_cron with schema pg_catalog;
do $$
declare j record;
begin
  for j in select jobid from cron.job where jobname = 'refresh-bomba-storage-usage' loop
    perform cron.unschedule(j.jobid);
  end loop;
  perform cron.schedule('refresh-bomba-storage-usage', '*/5 * * * *', 'select public.refresh_bomba_storage_usage();');
end $$;

select public.refresh_bomba_storage_usage();
