-- 0086_tenant_postgres_write_fence.sql — DATA-8715a151: extend the
-- full-erasure barrier from append-only audit rows to every ordinary
-- tenant-owned PostgreSQL writer.
--
-- An ordinary writer takes a transaction-scoped shared advisory lock before
-- INSERT/UPDATE and then reads the durable tenant registry row. Full erasure
-- takes the matching exclusive lock before changing the tenant to offboarding.
-- Therefore a pre-fence write finishes before deletion begins, while a writer
-- arriving during or after the transition waits and then fails closed.

COMMENT ON COLUMN public.tenants.audit_write_fenced_at IS
    'Write-once full-erasure barrier for all tenant-owned storage writers';

CREATE OR REPLACE FUNCTION public.probectl_enforce_tenant_write_fence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $tenant_write_fence$
DECLARE
    tenant_status text;
    tenant_fenced_at timestamptz;
BEGIN
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION
            'tenant write is missing tenant_id'
            USING ERRCODE = '42501';
    END IF;

    PERFORM pg_advisory_xact_lock_shared(
        hashtextextended('tenant-write:' || NEW.tenant_id::text, 0)
    );
    SELECT status, audit_write_fenced_at
      INTO tenant_status, tenant_fenced_at
      FROM public.tenants
     WHERE id = NEW.tenant_id;

    IF NOT FOUND
       OR tenant_fenced_at IS NOT NULL
       OR tenant_status NOT IN ('active', 'suspended') THEN
        RAISE EXCEPTION
            'tenant writes are fenced for lifecycle erasure'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$tenant_write_fence$;

REVOKE ALL
    ON FUNCTION public.probectl_enforce_tenant_write_fence()
    FROM PUBLIC;
GRANT EXECUTE
    ON FUNCTION public.probectl_enforce_tenant_write_fence()
    TO probectl_app, probectl_provider;

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

-- Existing silo schemas contain tenant-owned tables only. Apply the same
-- trigger to every ordinary table; future provision/catch-up plans emit the
-- identical recipe from ee/silo/planner.go.
DO $tenant_postgres_write_fence_silos$
DECLARE
    silo record;
    tenant_table record;
BEGIN
    FOR silo IN
        SELECT id::text AS tenant_id,
               't_' || replace(id::text, '-', '') AS schema_name
          FROM public.tenants
         WHERE isolation_model = 'siloed'
    LOOP
        FOR tenant_table IN
            SELECT c.relname AS table_name
              FROM pg_catalog.pg_class AS c
              JOIN pg_catalog.pg_namespace AS n
                ON n.oid = c.relnamespace
              JOIN pg_catalog.pg_attribute AS a
                ON a.attrelid = c.oid
               AND a.attname = 'tenant_id'
               AND NOT a.attisdropped
             WHERE n.nspname = silo.schema_name
               AND c.relkind IN ('r', 'p')
               AND c.relname NOT IN (
                   'audit_events',
                   'audit_subject_erasures'
               )
        LOOP
            EXECUTE format(
                'DROP TRIGGER IF EXISTS tenant_write_fence ON %I.%I',
                silo.schema_name,
                tenant_table.table_name
            );
            EXECUTE format(
                'CREATE TRIGGER tenant_write_fence
                    BEFORE INSERT OR UPDATE ON %I.%I
                    FOR EACH ROW
                    EXECUTE FUNCTION
                        public.probectl_enforce_tenant_write_fence()',
                silo.schema_name,
                tenant_table.table_name
            );
            EXECUTE format(
                'ALTER TABLE %I.%I
                    ENABLE ALWAYS TRIGGER tenant_write_fence',
                silo.schema_name,
                tenant_table.table_name
            );
        END LOOP;
    END LOOP;
END
$tenant_postgres_write_fence_silos$;
