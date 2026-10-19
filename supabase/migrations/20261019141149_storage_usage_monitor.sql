-- Storage monitor: exact database size and sum of file sizes in Supabase Storage.
-- The function is callable only by service_role; the Edge Function verifies the caller is the site owner.
create or replace function public.get_bomba_storage_usage()
returns table(database_bytes bigint, storage_bytes bigint)
language sql
security definer
set search_path = public, storage, pg_catalog
as $$
  select
    pg_database_size(current_database())::bigint as database_bytes,
    coalesce((
      select sum(
        case
          when coalesce(o.metadata->>'size', '') ~ '^[0-9]+$'
            then (o.metadata->>'size')::bigint
          else 0::bigint
        end
      )
      from storage.objects o
    ), 0)::bigint as storage_bytes;
$$;

revoke all on function public.get_bomba_storage_usage() from public;
revoke all on function public.get_bomba_storage_usage() from anon;
revoke all on function public.get_bomba_storage_usage() from authenticated;
grant execute on function public.get_bomba_storage_usage() to service_role;
