-- Private Storage bucket for Service Act photos. The app stores only the object path in app_state.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('service-acts-photos', 'service-acts-photos', false, 8388608, array['image/jpeg','image/png','image/webp'])
on conflict (id) do update
set public = false,
    file_size_limit = 8388608,
    allowed_mime_types = array['image/jpeg','image/png','image/webp'];

drop policy if exists "Service act photos readable by authenticated users" on storage.objects;
create policy "Service act photos readable by authenticated users"
on storage.objects for select to authenticated
using (bucket_id = 'service-acts-photos');

drop policy if exists "Service act photos uploadable by authenticated users" on storage.objects;
create policy "Service act photos uploadable by authenticated users"
on storage.objects for insert to authenticated
with check (bucket_id = 'service-acts-photos');

drop policy if exists "Service act photos updatable by authenticated users" on storage.objects;
create policy "Service act photos updatable by authenticated users"
on storage.objects for update to authenticated
using (bucket_id = 'service-acts-photos')
with check (bucket_id = 'service-acts-photos');

drop policy if exists "Service act photos deletable by authenticated users" on storage.objects;
create policy "Service act photos deletable by authenticated users"
on storage.objects for delete to authenticated
using (bucket_id = 'service-acts-photos');
