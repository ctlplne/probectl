-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Expand the existing report inbox. Legacy inline bytes are not rewritten.
-- lock-ok: constant defaults, nullable ADDs and a NOT VALID representation
-- CHECK avoid a historical body scan; DROP NOT NULL only follows that CHECK.
ALTER TABLE dashboard_report_artifacts ADD COLUMN IF NOT EXISTS body_storage text NOT NULL DEFAULT 'inline';
ALTER TABLE dashboard_report_artifacts ADD COLUMN IF NOT EXISTS body_bytes bigint;
ALTER TABLE dashboard_report_artifacts ADD COLUMN IF NOT EXISTS body_digest bytea;
ALTER TABLE dashboard_report_artifacts ADD COLUMN IF NOT EXISTS source_capture jsonb;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='dashboard_report_artifacts'::regclass
          AND conname='dashboard_report_artifacts_body_representation') THEN
        ALTER TABLE dashboard_report_artifacts
            ADD CONSTRAINT dashboard_report_artifacts_body_representation CHECK (
                (body_storage='inline' AND content IS NOT NULL
                 AND octet_length(content) BETWEEN 1 AND 2097152
                 AND source_capture IS NULL
                 AND (body_bytes IS NULL OR body_bytes=octet_length(content))
                 AND (body_digest IS NULL OR octet_length(body_digest)=32))
                OR
                (body_storage='chunks' AND content IS NULL
                 AND body_bytes IS NOT NULL AND body_bytes BETWEEN 1 AND 268435456
                 AND body_digest IS NOT NULL AND octet_length(body_digest)=32
                 AND source_capture IS NOT NULL AND jsonb_typeof(source_capture)='object'
                 AND source_capture @> '{"version":1}'::jsonb
                 AND source_capture->>'tenant_id' IS NOT NULL
                 AND source_capture->>'tenant_id'=tenant_id::text
                 AND octet_length(source_capture::text)<=1048576)
            ) NOT VALID;
    END IF;
END $$;
ALTER TABLE dashboard_report_artifacts ALTER COLUMN content DROP NOT NULL;

-- A pre-chunk reader otherwise decodes NULL bytea as an empty successful
-- download. The capability is request-local and confers no tenant or RBAC
-- authority. Recheck tenant here before any format error, independently of
-- planner ordering with the outer tenant policy (docs/guardrails.md G7-1).
CREATE OR REPLACE FUNCTION public.probectl_report_artifact_format_allowed(
    row_tenant uuid, row_storage text, row_capture jsonb
) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY INVOKER
SET search_path = pg_catalog
AS $$
DECLARE expected_tenant text := NULLIF(current_setting('probectl.tenant_id', true), '');
BEGIN
    IF expected_tenant IS NULL OR row_tenant IS DISTINCT FROM expected_tenant::uuid THEN
        RETURN false;
    END IF;
    IF row_storage='inline' AND row_capture IS NULL THEN
        RETURN true;
    END IF;
    IF current_setting('probectl.report_artifact_format', true)='1' THEN
        RETURN true;
    END IF;
    RAISE EXCEPTION USING ERRCODE='0A000',
        MESSAGE='report artifact format requires an upgraded reader';
END;
$$;
REVOKE ALL ON FUNCTION public.probectl_report_artifact_format_allowed(uuid,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.probectl_report_artifact_format_allowed(uuid,text,jsonb) TO probectl_app;

DROP POLICY IF EXISTS report_artifact_format ON dashboard_report_artifacts;
CREATE POLICY report_artifact_format ON dashboard_report_artifacts AS RESTRICTIVE
    USING (public.probectl_report_artifact_format_allowed(tenant_id,body_storage,source_capture))
    WITH CHECK (public.probectl_report_artifact_format_allowed(tenant_id,body_storage,source_capture));
REVOKE UPDATE ON dashboard_report_artifacts FROM probectl_app;

CREATE TABLE IF NOT EXISTS dashboard_report_artifact_chunks (
    tenant_id uuid NOT NULL,
    artifact_id text NOT NULL,
    ordinal integer NOT NULL CHECK (ordinal BETWEEN 0 AND 4095),
    content bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 65536),
    PRIMARY KEY (tenant_id,artifact_id,ordinal),
    CONSTRAINT dashboard_report_artifact_chunks_artifact_fk
        FOREIGN KEY (tenant_id,artifact_id)
        REFERENCES dashboard_report_artifacts(tenant_id,id) ON DELETE CASCADE
);
ALTER TABLE dashboard_report_artifact_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE dashboard_report_artifact_chunks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON dashboard_report_artifact_chunks;
CREATE POLICY tenant_isolation ON dashboard_report_artifact_chunks
    USING (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);
GRANT SELECT,INSERT,DELETE ON dashboard_report_artifact_chunks TO probectl_app;
REVOKE UPDATE ON dashboard_report_artifact_chunks FROM probectl_app;
