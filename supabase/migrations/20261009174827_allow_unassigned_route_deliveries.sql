-- Deliveries without an assigned driver must remain available for dispatch.
alter table public.deliveries alter column driver_id drop not null;
