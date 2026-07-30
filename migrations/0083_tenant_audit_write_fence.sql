-- 0083_tenant_audit_write_fence.sql — DATA-6814b317: close the
-- full-tenant-erasure race on both append-only tenant audit tables.
--
-- The lifecycle engine changes tenants to offboarding while it owns the same
-- advisory lock used by audit appenders. The trigger below puts that lock at
-- the storage boundary as well, so a rolling-old writer cannot bypass the
-- barrier. Its locking read observes the current tenant row after any wait;
-- the restrictive policy is defense in depth for ordinary runtime writes.

ALTER TABLE public.tenants
    ADD COLUMN IF NOT EXISTS audit_write_fenced_at timestamptz;

COMMENT ON COLUMN public.tenants.audit_write_fenced_at IS
    'Write-once full-erasure barrier for tenant audit append paths';

UPDATE public.tenants
   SET audit_write_fenced_at = COALESCE(updated_at, now())
 WHERE status = 'deleted'
   AND audit_write_fenced_at IS NULL;

CREATE OR REPLACE FUNCTION public.probectl_preserve_tenant_audit_write_fence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $preserve_tenant_audit_write_fence$
BEGIN
    IF OLD.audit_write_fenced_at IS NOT NULL
       AND NEW.audit_write_fenced_at IS DISTINCT FROM
           OLD.audit_write_fenced_at THEN
        RAISE EXCEPTION
            'tenant audit erasure fence is irreversible'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.audit_write_fenced_at IS NOT NULL
       AND NEW.status NOT IN ('offboarding', 'deleted') THEN
        RAISE EXCEPTION
            'tenant under audit erasure fence must remain offboarding or deleted'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$preserve_tenant_audit_write_fence$;

REVOKE ALL
    ON FUNCTION public.probectl_preserve_tenant_audit_write_fence()
    FROM PUBLIC;

DROP TRIGGER IF EXISTS preserve_tenant_audit_write_fence
    ON public.tenants;
CREATE TRIGGER preserve_tenant_audit_write_fence
    BEFORE UPDATE OF audit_write_fenced_at, status ON public.tenants
    FOR EACH ROW
    EXECUTE FUNCTION public.probectl_preserve_tenant_audit_write_fence();
ALTER TABLE public.tenants
    ENABLE ALWAYS TRIGGER preserve_tenant_audit_write_fence;

CREATE OR REPLACE FUNCTION public.probectl_tenant_audit_writes_allowed()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $tenant_audit_writes_allowed$
    SELECT EXISTS (
        SELECT 1
          FROM public.tenants
         WHERE id =
               NULLIF(
                   current_setting('probectl.tenant_id', true),
                   ''
               )::uuid
           AND status IN ('active', 'suspended')
           AND audit_write_fenced_at IS NULL
    )
$tenant_audit_writes_allowed$;

REVOKE ALL
    ON FUNCTION public.probectl_tenant_audit_writes_allowed()
    FROM PUBLIC;
GRANT EXECUTE
    ON FUNCTION public.probectl_tenant_audit_writes_allowed()
    TO probectl_app, probectl_provider;

CREATE OR REPLACE FUNCTION public.probectl_enforce_tenant_audit_write_fence()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $tenant_audit_write_fence$
DECLARE
    bound_tenant uuid;
    tenant_fenced_at timestamptz;
    tenant_status text;
    runtime_role text;
BEGIN
    -- Runtime roles must also prove their tenant binding. Migration/fixture
    -- owners may omit the GUC, but they still take the same stream lock and
    -- can never write across an established erasure fence.
    runtime_role := current_setting('role', true);
    IF runtime_role IN ('probectl_app', 'probectl_provider') THEN
        bound_tenant :=
            NULLIF(current_setting('probectl.tenant_id', true), '')::uuid;
        IF bound_tenant IS NULL
           OR NEW.tenant_id IS DISTINCT FROM bound_tenant THEN
            RAISE EXCEPTION
                'tenant audit write is not bound to the current tenant'
                USING ERRCODE = '42501';
        END IF;
    END IF;

    -- This key is byte-for-byte identical to internal/audit.LockTenantStream.
    -- The locking row read is intentional: after waiting for an erasure fence,
    -- READ COMMITTED must inspect the newly committed status, not the INSERT
    -- statement's earlier snapshot.
    PERFORM pg_advisory_xact_lock(
        hashtextextended('audit:' || NEW.tenant_id::text, 0)
    );
    SELECT status, audit_write_fenced_at
      INTO tenant_status, tenant_fenced_at
      FROM public.tenants
     WHERE id = NEW.tenant_id
     FOR KEY SHARE;

    IF NOT FOUND
       OR tenant_fenced_at IS NOT NULL
       OR (
           tenant_status IS DISTINCT FROM 'active'
           AND tenant_status IS DISTINCT FROM 'suspended'
       ) THEN
        RAISE EXCEPTION
            'tenant audit writes are fenced for lifecycle erasure'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$tenant_audit_write_fence$;

REVOKE ALL
    ON FUNCTION public.probectl_enforce_tenant_audit_write_fence()
    FROM PUBLIC;
GRANT EXECUTE
    ON FUNCTION public.probectl_enforce_tenant_audit_write_fence()
    TO probectl_app, probectl_provider;

DROP POLICY IF EXISTS tenant_audit_write_eligibility
    ON public.audit_events;
CREATE POLICY tenant_audit_write_eligibility
    ON public.audit_events AS RESTRICTIVE
    FOR INSERT TO probectl_app
    WITH CHECK (public.probectl_tenant_audit_writes_allowed());

DROP POLICY IF EXISTS tenant_audit_write_eligibility
    ON public.audit_subject_erasures;
CREATE POLICY tenant_audit_write_eligibility
    ON public.audit_subject_erasures AS RESTRICTIVE
    FOR INSERT TO probectl_app, probectl_provider
    WITH CHECK (public.probectl_tenant_audit_writes_allowed());

DROP TRIGGER IF EXISTS tenant_audit_write_fence
    ON public.audit_events;
CREATE TRIGGER tenant_audit_write_fence
    BEFORE INSERT ON public.audit_events
    FOR EACH ROW
    EXECUTE FUNCTION public.probectl_enforce_tenant_audit_write_fence();
ALTER TABLE public.audit_events
    ENABLE ALWAYS TRIGGER tenant_audit_write_fence;

DROP TRIGGER IF EXISTS tenant_audit_write_fence
    ON public.audit_subject_erasures;
CREATE TRIGGER tenant_audit_write_fence
    BEFORE INSERT ON public.audit_subject_erasures
    FOR EACH ROW
    EXECUTE FUNCTION public.probectl_enforce_tenant_audit_write_fence();
ALTER TABLE public.audit_subject_erasures
    ENABLE ALWAYS TRIGGER tenant_audit_write_fence;

-- Converge every already-provisioned silo. Future provision/catch-up plans
-- emit the same policies and triggers from ee/silo/planner.go.
DO $tenant_audit_write_fence_silos$
DECLARE
    silo record;
    table_name text;
    runtime_roles text;
BEGIN
    FOR silo IN
        SELECT id::text AS tenant_id,
               't_' || replace(id::text, '-', '') AS schema_name
          FROM public.tenants
         WHERE isolation_model = 'siloed'
    LOOP
        FOREACH table_name IN ARRAY
            ARRAY['audit_events', 'audit_subject_erasures']
        LOOP
            IF to_regclass(
                format('%I.%I', silo.schema_name, table_name)
            ) IS NULL THEN
                CONTINUE;
            END IF;

            runtime_roles := CASE table_name
                WHEN 'audit_events' THEN 'probectl_app'
                ELSE 'probectl_app, probectl_provider'
            END;
            EXECUTE format(
                'DROP POLICY IF EXISTS tenant_audit_write_eligibility
                     ON %I.%I',
                silo.schema_name,
                table_name
            );
            EXECUTE format(
                'CREATE POLICY tenant_audit_write_eligibility
                     ON %I.%I AS RESTRICTIVE
                    FOR INSERT TO %s
                  WITH CHECK (
                      public.probectl_tenant_audit_writes_allowed()
                  )',
                silo.schema_name,
                table_name,
                runtime_roles
            );
            EXECUTE format(
                'DROP TRIGGER IF EXISTS tenant_audit_write_fence
                     ON %I.%I',
                silo.schema_name,
                table_name
            );
            EXECUTE format(
                'CREATE TRIGGER tenant_audit_write_fence
                    BEFORE INSERT ON %I.%I
                    FOR EACH ROW
                    EXECUTE FUNCTION
                        public.probectl_enforce_tenant_audit_write_fence()',
                silo.schema_name,
                table_name
            );
            EXECUTE format(
                'ALTER TABLE %I.%I
                    ENABLE ALWAYS TRIGGER tenant_audit_write_fence',
                silo.schema_name,
                table_name
            );
        END LOOP;
    END LOOP;
END
$tenant_audit_write_fence_silos$;
