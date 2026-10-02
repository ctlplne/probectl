-- 0113_tenant_write_fence_web26_backfill.sql
-- WEB-26: migration 0104 (device_syslog, device_configs) and 0105
-- (inventory_saved_views) created new public tenant_id tables AFTER the
-- discovery backfill in 0102, so the Postgres tenant write fence — which rejects
-- INSERT/UPDATE from an erased or suspended tenant inside PostgreSQL itself, the
-- table owner included — was never installed on them. Guardrail 1 (G7-1) says the
-- tenant boundary is enforced in the storage layer; for these three tables it was
-- not, so a fenced tenant's writes to its device syslog/config archive and saved
-- inventory views would still be accepted.
--
-- These are ordinary tenant data (not provider-owned, not append-only audit), so
-- each gets the same generic fence 0102 installs, applied here to exactly the
-- three tables 0102 predated. Idempotent by construction: DROP TRIGGER IF EXISTS
-- then CREATE, so re-running on an already-fenced table is a no-op. The fence
-- function public.probectl_enforce_tenant_write_fence() comes from migration 0086.
DO $tenant_write_fence_web26$
DECLARE
    tenant_table text;
BEGIN
    FOREACH tenant_table IN ARRAY ARRAY['device_syslog', 'device_configs', 'inventory_saved_views']
    LOOP
        EXECUTE format(
            'DROP TRIGGER IF EXISTS tenant_write_fence ON public.%I',
            tenant_table
        );
        EXECUTE format(
            'CREATE TRIGGER tenant_write_fence
                BEFORE INSERT OR UPDATE ON public.%I
                FOR EACH ROW
                EXECUTE FUNCTION
                    public.probectl_enforce_tenant_write_fence()',
            tenant_table
        );
        EXECUTE format(
            'ALTER TABLE public.%I
                ENABLE ALWAYS TRIGGER tenant_write_fence',
            tenant_table
        );
    END LOOP;
END
$tenant_write_fence_web26$;
