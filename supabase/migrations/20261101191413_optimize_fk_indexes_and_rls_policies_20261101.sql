-- Add indexes for the three foreign keys identified by Supabase Performance Advisor.
-- These are additive and preserve all existing rows and constraints.
CREATE INDEX IF NOT EXISTS app_state_updated_by_idx ON public.app_state (updated_by);
CREATE INDEX IF NOT EXISTS route_deliveries_delivery_id_idx ON public.route_deliveries (delivery_id);
CREATE INDEX IF NOT EXISTS route_locations_driver_id_idx ON public.route_locations (driver_id);

-- Cache auth.uid() once per statement instead of recalculating it per candidate row.
DROP POLICY IF EXISTS "authenticated can insert app state" ON public.app_state;
CREATE POLICY "authenticated can insert app state" ON public.app_state FOR INSERT TO authenticated
  WITH CHECK (updated_by = (SELECT auth.uid()));
DROP POLICY IF EXISTS "authenticated can update app state" ON public.app_state;
CREATE POLICY "authenticated can update app state" ON public.app_state FOR UPDATE TO authenticated
  USING (true) WITH CHECK (updated_by = (SELECT auth.uid()));
DROP POLICY IF EXISTS "site owners can read email send logs" ON public.email_send_logs;
CREATE POLICY "site owners can read email send logs" ON public.email_send_logs FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.profiles p WHERE p.id = (SELECT auth.uid()) AND lower(p.group_name) = lower('Владельцы')));
