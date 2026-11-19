-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- The registry projection lets telemetry writers check the same deadline
-- under their existing tenant lease without opening tenant report data.
-- lock-ok: nullable field and scoped trigger metadata, with no table rewrite.
ALTER TABLE public.tenants ADD COLUMN IF NOT EXISTS prospect_collection_ends_at timestamptz;

CREATE OR REPLACE FUNCTION public.probectl_project_prospect_collection_deadline()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $prospect_collection_deadline$
BEGIN
    IF TG_TABLE_NAME <> 'prospect_engagements'
       OR NULLIF(current_setting('probectl.tenant_id', true), '') IS DISTINCT FROM NEW.tenant_id::text THEN
        RAISE EXCEPTION 'prospect collection scope differs' USING ERRCODE = '42501';
    END IF;

    UPDATE public.tenants
       SET prospect_collection_ends_at = CASE WHEN NEW.converted_at IS NULL THEN NEW.ends_at END
     WHERE id = NEW.tenant_id AND status IN ('active', 'suspended') AND audit_write_fenced_at IS NULL
       AND TG_TABLE_SCHEMA = CASE WHEN isolation_model = 'siloed'
           THEN 't_' || replace(id::text, '-', '') ELSE 'public' END;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'prospect collection registry is unavailable' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END
$prospect_collection_deadline$;

REVOKE ALL ON FUNCTION public.probectl_project_prospect_collection_deadline() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_project_prospect_collection_deadline() TO probectl_app;

-- Resolve each previous engagement through its active tenant scope. Future
-- changes use the same projection through the trigger.
DO $prospect_collection_backfill$
DECLARE
    tenant record;
    route text;
    previous_scope text := current_setting('probectl.tenant_id', true);
BEGIN
    FOR tenant IN SELECT id,isolation_model FROM public.tenants
                   WHERE status IN ('active','suspended') AND audit_write_fenced_at IS NULL
    LOOP
        route := CASE WHEN tenant.isolation_model = 'siloed'
            THEN 't_' || replace(tenant.id::text, '-', '') ELSE 'public' END;
        IF to_regclass(format('%I.prospect_engagements',route)) IS NULL THEN
            CONTINUE;
        END IF;
        PERFORM set_config('probectl.tenant_id',tenant.id::text,true);
        EXECUTE format('UPDATE public.tenants t
            SET prospect_collection_ends_at=CASE WHEN p.converted_at IS NULL THEN p.ends_at END
            FROM %I.prospect_engagements p WHERE t.id=$1 AND p.tenant_id=t.id
            AND t.status IN (''active'',''suspended'') AND t.audit_write_fenced_at IS NULL', route) USING tenant.id;
    END LOOP;
    PERFORM set_config('probectl.tenant_id',COALESCE(previous_scope,''),true);
END
$prospect_collection_backfill$;

DO $prospect_collection_schemas$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT n.nspname AS schema_name FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON c.relnamespace=n.oid
        WHERE c.relname='prospect_engagements' AND c.relkind IN ('r','p')
          AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS prospect_collection_deadline ON %I.prospect_engagements', target.schema_name);
        EXECUTE format('CREATE TRIGGER prospect_collection_deadline AFTER INSERT OR UPDATE OF ends_at, converted_at ON %I.prospect_engagements FOR EACH ROW EXECUTE FUNCTION public.probectl_project_prospect_collection_deadline()', target.schema_name);
        EXECUTE format('ALTER TABLE %I.prospect_engagements ENABLE ALWAYS TRIGGER prospect_collection_deadline', target.schema_name);
    END LOOP;
END
$prospect_collection_schemas$;
