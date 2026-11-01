-- Preserve the existing template background while removing it from the frequently
-- synchronized app_state JSON. The trigger also protects against older browser tabs.
create table if not exists public.service_template_assets (
  id text primary key check (id = 'service'),
  background text not null,
  updated_at timestamptz not null default now(),
  updated_by uuid
);

alter table public.service_template_assets enable row level security;
drop policy if exists "authenticated can read service template asset" on public.service_template_assets;
drop policy if exists "authenticated can insert service template asset" on public.service_template_assets;
drop policy if exists "authenticated can update service template asset" on public.service_template_assets;
create policy "authenticated can read service template asset"
  on public.service_template_assets for select to authenticated using (true);
create policy "authenticated can insert service template asset"
  on public.service_template_assets for insert to authenticated
  with check (updated_by = (select auth.uid()));
create policy "authenticated can update service template asset"
  on public.service_template_assets for update to authenticated
  using (true) with check (updated_by = (select auth.uid()));
grant select, insert, update on public.service_template_assets to authenticated;
revoke all on public.service_template_assets from anon;

create or replace function public.extract_service_template_background()
returns trigger
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  cfg jsonb;
  bg text;
begin
  cfg := new.payload #> '{siteSettings,serviceTemplateConfig}';
  bg := cfg ->> 'background';
  if bg is not null and bg <> '' then
    insert into public.service_template_assets (id, background, updated_at, updated_by)
    values ('service', bg, coalesce(new.updated_at, now()), new.updated_by)
    on conflict (id) do update
      set background = excluded.background,
          updated_at = excluded.updated_at,
          updated_by = excluded.updated_by
      where public.service_template_assets.background is distinct from excluded.background;
    new.payload := jsonb_set(
      new.payload,
      '{siteSettings,serviceTemplateConfig}',
      coalesce(cfg, '{}'::jsonb) - 'background',
      true
    );
  end if;
  return new;
end;
$$;
revoke all on function public.extract_service_template_background() from public, anon, authenticated;

drop trigger if exists trg_extract_service_template_background on public.app_state;
create trigger trg_extract_service_template_background
before insert or update of payload on public.app_state
for each row execute function public.extract_service_template_background();

-- One-time, lossless extraction of the existing background before removing it
-- from app_state. Do not overwrite an already extracted asset.
insert into public.service_template_assets (id, background, updated_at, updated_by)
select 'service', payload #>> '{siteSettings,serviceTemplateConfig,background}', updated_at, updated_by
from public.app_state
where id = 'main'
  and coalesce(payload #>> '{siteSettings,serviceTemplateConfig,background}', '') <> ''
on conflict (id) do nothing;

update public.app_state
set payload = jsonb_set(
      payload,
      '{siteSettings,serviceTemplateConfig}',
      coalesce(payload #> '{siteSettings,serviceTemplateConfig}', '{}'::jsonb) - 'background',
      true
    )
where id = 'main'
  and coalesce(payload #>> '{siteSettings,serviceTemplateConfig,background}', '') <> '';

-- Missing email addresses are a valid reason for a skipped/failed notification;
-- keep the diagnostic row instead of failing the log insert itself.
alter table public.email_send_logs
  alter column recipient_email drop not null;

-- Keep the presence RPC callable only by authenticated sessions. The client now
-- checks for a live auth session before sending heartbeats.
grant execute on function public.touch_my_account_presence() to authenticated;
grant execute on function public.get_account_presence() to authenticated;

-- Realtime subscription for the separately stored template background.
do $$
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime')
     and not exists (
       select 1 from pg_publication_tables
       where pubname = 'supabase_realtime'
         and schemaname = 'public'
         and tablename = 'service_template_assets'
     ) then
    alter publication supabase_realtime add table public.service_template_assets;
  end if;
end;
$$;
