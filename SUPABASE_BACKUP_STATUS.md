# Supabase backup — 2026-11-22

A logical snapshot was created in the Supabase project **before** applying the access-control and audit migrations.

- Snapshot schema: `backup_before_audit_security_20261122`
- Snapshot timestamp: `2026-11-22 18:57:22 UTC`
- Captured: 18 public application tables, 8 Auth user records in a restricted safe-copy table, Storage bucket/object metadata (2 buckets and 5 object records), plus snapshots of database function, policy, and trigger definitions.
- The backup schema has access revoked from `PUBLIC`, `anon`, and `authenticated`.

**Important limitation:** this snapshot is stored inside the same Supabase database. It is useful for recovering database table data and reviewing the pre-change definitions, but it is not an independent disaster-recovery backup. Storage file bytes, project secrets, Auth configuration, and deployed Edge Function bundles are not included. Keep the schema intact until a separate export/managed backup has been made.
