-- Enable live cross-user updates for the shared application state.
-- This migration was applied directly to the production Supabase project.
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
