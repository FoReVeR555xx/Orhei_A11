-- Fix owner-only read policy: public.profiles has no role column.
drop policy if exists "site owners can read email send logs" on public.email_send_logs;
create policy "site owners can read email send logs"
on public.email_send_logs
for select
to authenticated
using (
  exists (
    select 1
    from public.profiles p
    where p.id = auth.uid()
      and lower(p.group_name) = lower('Владельцы')
  )
);
