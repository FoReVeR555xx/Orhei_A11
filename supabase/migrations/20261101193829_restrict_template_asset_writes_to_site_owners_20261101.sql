DROP POLICY IF EXISTS "authenticated can insert service template asset" ON public.service_template_assets;
DROP POLICY IF EXISTS "authenticated can update service template asset" ON public.service_template_assets;
CREATE POLICY "site owners can insert service template asset" ON public.service_template_assets FOR INSERT TO authenticated
WITH CHECK (updated_by = (SELECT auth.uid()) AND EXISTS (
  SELECT 1 FROM public.profiles p WHERE p.id = (SELECT auth.uid()) AND lower(btrim(p.group_name)) = 'владельцы'));
CREATE POLICY "site owners can update service template asset" ON public.service_template_assets FOR UPDATE TO authenticated
USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = (SELECT auth.uid()) AND lower(btrim(p.group_name)) = 'владельцы'))
WITH CHECK (updated_by = (SELECT auth.uid()) AND EXISTS (
  SELECT 1 FROM public.profiles p WHERE p.id = (SELECT auth.uid()) AND lower(btrim(p.group_name)) = 'владельцы'));
