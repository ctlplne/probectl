-- 0117_alert_notifications_write_fence.sql
-- RTO-20 follow-up: migration 0115 created the public tenant_id table
-- alert_notifications AFTER the write-fence backfill (0113), so the Postgres
-- tenant write fence -- which rejects INSERT/UPDATE from an erased or suspended
-- tenant inside PostgreSQL itself, the table owner included -- was never
-- installed on it. Guardrail 1 (G7-1) says the tenant boundary is enforced in
-- the storage layer; for this table only RLS scoped it, so a fenced (offboarded)
-- tenant's renotify bookkeeping writes would still be accepted at the owner
-- level. The public-table write-fence coverage test
-- (internal/tenantlife/postgres_write_fence_integration_test.go) asserts every
-- tenant-owned public table except the append-only audit tables carries it.
--
-- alert_notifications is ordinary tenant data (not provider-owned, not
-- append-only audit), so it gets the same generic fence 0086 defines, applied
-- here the same way 0113 applied it to the tables 0102 predated. Idempotent by
-- construction: DROP TRIGGER IF EXISTS then CREATE, so re-running on an
-- already-fenced table is a no-op. The fence function
-- public.probectl_enforce_tenant_write_fence() comes from migration 0086.
DO $alert_notifications_write_fence$
BEGIN
    DROP TRIGGER IF EXISTS tenant_write_fence ON public.alert_notifications;
    CREATE TRIGGER tenant_write_fence
        BEFORE INSERT OR UPDATE ON public.alert_notifications
        FOR EACH ROW
        EXECUTE FUNCTION
            public.probectl_enforce_tenant_write_fence();
    ALTER TABLE public.alert_notifications
        ENABLE ALWAYS TRIGGER tenant_write_fence;
END
$alert_notifications_write_fence$;
