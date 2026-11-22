-- NULL user_id denotes a global rule; PostgreSQL UNIQUE treats NULL values as distinct,
-- so enforce uniqueness for global entries separately.
create unique index if not exists device_access_rules_global_unique_idx
  on public.device_access_rules (kind, value, mode)
  where user_id is null;
