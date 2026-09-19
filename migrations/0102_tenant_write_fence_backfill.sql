-- 0102_tenant_write_fence_backfill.sql
-- DPR-215: the Postgres tenant write fence is attached by DISCOVERY — migration
-- 0086 walks every public table carrying a tenant_id and installs the
-- tenant_write_fence trigger on each. That is self-maintaining for the tables
-- that existed when 0086 ran, and silently incomplete for every tenant table
-- created afterwards.
--
-- Four were: alert_active_state and alert_evaluator_status (0095),
-- compliance_alerted (0096) and cost_budget_alerted (0099). On any deployment
-- that upgraded through 0086 and then past 0095, those four accept writes from
-- an erased or suspended tenant, because the fence that rejects them inside
-- PostgreSQL itself — table owner included — was never put on. Guardrail 1 says
-- the boundary is enforced at the storage layer, and for these tables it was not.
--
-- Re-running the same discovery is the fix, and it is idempotent by
-- construction: DROP TRIGGER IF EXISTS then CREATE, on whatever is missing it
-- today. It therefore also covers any table added between 0086 and now that
-- nobody noticed, not just the four the tests named.
--
-- The exclusion list is 0086's, unchanged: those tables are deliberately
-- writable while a tenant is fenced (audit and erasure projections must still
-- record the erasure; usage and quota rows outlive the tenant).


-- Provider-owned records about a tenant are finalized by the lifecycle engine
-- after the tenant fence, and the append-only audit tables retain their
-- stronger stream-lock trigger from migration 0083. Every remaining public
-- tenant_id table is ordinary tenant data and gets the generic fence.
DO $tenant_postgres_write_fence_public$
DECLARE
    tenant_table record;
BEGIN
    FOR tenant_table IN
        SELECT c.relname AS table_name
          FROM pg_catalog.pg_class AS c
          JOIN pg_catalog.pg_namespace AS n
            ON n.oid = c.relnamespace
          JOIN pg_catalog.pg_attribute AS a
            ON a.attrelid = c.oid
           AND a.attname = 'tenant_id'
           AND NOT a.attisdropped
         WHERE n.nspname = 'public'
           AND c.relkind IN ('r', 'p')
           AND c.relname NOT IN (
               'audit_events',
               'audit_subject_erasures',
               'audit_stream_heads',
               'break_glass_grants',
               'usage_records',
               'tenant_quotas',
               'tenant_branding',
               'tenant_retention',
               'tenant_keys',
               'tenant_fairness',
               'tenant_governance',
               'ir_attribution_heads',
               'ir_key_shred_records',
               'ir_key_shred_heads',
               'ir_post_shred_attempt_records',
               'ir_post_shred_attempt_heads',
               'credential_locators',
               'agent_identity_revocations'
           )
    LOOP
        EXECUTE format(
            'DROP TRIGGER IF EXISTS tenant_write_fence ON public.%I',
            tenant_table.table_name
        );
        EXECUTE format(
            'CREATE TRIGGER tenant_write_fence
                BEFORE INSERT OR UPDATE ON public.%I
                FOR EACH ROW
                EXECUTE FUNCTION
                    public.probectl_enforce_tenant_write_fence()',
            tenant_table.table_name
        );
        EXECUTE format(
            'ALTER TABLE public.%I
                ENABLE ALWAYS TRIGGER tenant_write_fence',
            tenant_table.table_name
        );
    END LOOP;
END
$tenant_postgres_write_fence_public$;
