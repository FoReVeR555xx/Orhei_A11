-- Historical migration-history alignment for the existing Supabase project.
-- The pre-change safety backups were created directly in the production database
-- before this repository's migration files were assembled. Their data is specific
-- to that production database and must not be recreated in Preview environments.
-- This no-op preserves the remote migration version without overwriting or
-- fabricating backup data. Application schema changes live in later migrations.
select 1;
