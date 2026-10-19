-- Cancel scheduled notification emails as soon as their notification is removed,
-- its recipient is removed, or the recipient has already read it.
create or replace function public.cancel_scheduled_emails_for_missing_notifications()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  announcements jsonb;
begin
  if coalesce(new.id, '') <> 'main' then return new; end if;
  announcements := case when jsonb_typeof(new.payload->'announcements') = 'array' then new.payload->'announcements' else '[]'::jsonb end;
  update public.email_send_logs l
     set status = 'skipped',
         error_message = case when exists (select 1 from jsonb_array_elements(announcements) n where n->>'id' = l.notification_id)
           then 'Отменено: уведомление прочитано или получатель больше не назначен.'
           else 'Отменено: исходное уведомление удалено или Сервис-Акт обработан.' end
   where l.status = 'scheduled'
     and not exists (
       select 1 from jsonb_array_elements(announcements) n
        where n->>'id' = l.notification_id
          and exists (select 1 from jsonb_array_elements(case when jsonb_typeof(n->'recipients') = 'array' then n->'recipients' else '[]'::jsonb end) r where lower(trim(r #>> '{}')) = lower(trim(l.recipient_login)))
          and not exists (select 1 from jsonb_array_elements(case when jsonb_typeof(n->'readBy') = 'array' then n->'readBy' else '[]'::jsonb end) rb where lower(trim(rb #>> '{}')) = lower(trim(l.recipient_login)))
     );
  return new;
end;
$$;
drop trigger if exists trg_cancel_scheduled_emails_for_missing_notifications on public.app_state;
create trigger trg_cancel_scheduled_emails_for_missing_notifications after update of payload on public.app_state for each row execute function public.cancel_scheduled_emails_for_missing_notifications();
