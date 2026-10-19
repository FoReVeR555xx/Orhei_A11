-- Compatibility migration for the version already recorded in Supabase migration history.
-- This file is required so Supabase Preview can match the remote migration version.
-- Realtime setup is idempotent and safely skips tables already in the publication.
do $$ begin
  if not exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    create publication supabase_realtime;
  end if;
end $$;

do $$ declare t text; begin
  foreach t in array array['app_state','services','orders','profiles'] loop
    if to_regclass('public.' || t) is not null
       and not exists (
         select 1 from pg_publication_tables
         where pubname='supabase_realtime' and schemaname='public' and tablename=t
       ) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;
