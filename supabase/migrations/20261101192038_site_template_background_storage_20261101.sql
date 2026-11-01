-- Existing public bucket for owner-managed site/template assets.
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES ('site-assets', 'site-assets', true, 12582912, ARRAY['image/jpeg','image/png','image/webp','image/svg+xml'])
ON CONFLICT (id) DO UPDATE SET public = true, file_size_limit = 12582912,
  allowed_mime_types = ARRAY['image/jpeg','image/png','image/webp','image/svg+xml'];

DROP POLICY IF EXISTS "Site template assets uploadable by owners" ON storage.objects;
CREATE POLICY "Site template assets uploadable by owners" ON storage.objects FOR INSERT TO authenticated
WITH CHECK (bucket_id = 'site-assets' AND name LIKE 'templates/%' AND EXISTS (
  SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND lower(btrim(p.group_name)) = 'владельцы'));
DROP POLICY IF EXISTS "Site template assets updatable by owners" ON storage.objects;
CREATE POLICY "Site template assets updatable by owners" ON storage.objects FOR UPDATE TO authenticated
USING (bucket_id = 'site-assets' AND name LIKE 'templates/%' AND EXISTS (
  SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND lower(btrim(p.group_name)) = 'владельцы'))
WITH CHECK (bucket_id = 'site-assets' AND name LIKE 'templates/%' AND EXISTS (
  SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND lower(btrim(p.group_name)) = 'владельцы'));
DROP POLICY IF EXISTS "Site template assets deletable by owners" ON storage.objects;
CREATE POLICY "Site template assets deletable by owners" ON storage.objects FOR DELETE TO authenticated
USING (bucket_id = 'site-assets' AND name LIKE 'templates/%' AND EXISTS (
  SELECT 1 FROM public.profiles p WHERE p.id = auth.uid() AND lower(btrim(p.group_name)) = 'владельцы'));
