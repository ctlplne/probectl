-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Canonical role/routing sources retain complete current-context requirements
-- in version 2 receipts. Version 1 remains readable for ordinary/tag sources.
-- lock-ok: add compatible NOT VALID shape before dropping superseded checks;
-- no historical body rewrite/scan, RLS, ACL, format capability or fence change.
DO $report_context_receipts$
DECLARE target record; shape text := $shape$((body_storage='inline' AND content IS NOT NULL
        AND octet_length(content) BETWEEN 1 AND 2097152 AND source_capture IS NULL
        AND (body_bytes IS NULL OR body_bytes=octet_length(content))
        AND (body_digest IS NULL OR octet_length(body_digest)=32))
      OR (body_storage='chunks' AND content IS NULL
        AND body_bytes IS NOT NULL AND body_bytes BETWEEN 1 AND 140737488355328
        AND body_digest IS NOT NULL AND octet_length(body_digest)=32
        AND source_capture IS NOT NULL AND jsonb_typeof(source_capture)='object'
        AND (source_capture @> '{"version":1}'::jsonb OR source_capture @> '{"version":2}'::jsonb)
        AND source_capture->>'tenant_id' IS NOT NULL
        AND source_capture->>'tenant_id'=tenant_id::text
        AND octet_length(source_capture::text)<=1048576)
      OR (body_storage='document-chunks' AND content IS NULL AND source_capture IS NULL
        AND body_bytes IS NOT NULL AND body_bytes BETWEEN 1 AND 140737488355328
        AND body_digest IS NOT NULL AND octet_length(body_digest)=32))$shape$;
BEGIN
    FOR target IN
        SELECT n.nspname
        FROM pg_namespace n JOIN pg_class c ON c.relnamespace=n.oid
        WHERE c.relname='dashboard_report_artifacts' AND c.relkind IN ('r','p')
          AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
            WHERE conrelid=format('%I.dashboard_report_artifacts',target.nspname)::regclass
              AND conname='dashboard_report_artifacts_body_representation_v4') THEN
            EXECUTE format('ALTER TABLE %I.dashboard_report_artifacts ADD CONSTRAINT dashboard_report_artifacts_body_representation_v4 CHECK %s NOT VALID',target.nspname,shape);
        END IF;
        EXECUTE format('ALTER TABLE %I.dashboard_report_artifacts DROP CONSTRAINT IF EXISTS dashboard_report_artifacts_body_representation_v3',target.nspname);
        EXECUTE format('ALTER TABLE %I.dashboard_report_artifacts DROP CONSTRAINT IF EXISTS dashboard_report_artifacts_body_representation_v2',target.nspname);
        EXECUTE format('ALTER TABLE %I.dashboard_report_artifacts DROP CONSTRAINT IF EXISTS dashboard_report_artifacts_body_representation',target.nspname);
    END LOOP;
END
$report_context_receipts$;
