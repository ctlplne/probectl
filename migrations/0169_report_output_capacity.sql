-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Output size is positive operator admission. The storage representation can
-- address 2^31 64-KiB chunks through its nonnegative integer ordinal.
-- lock-ok: add compatible NOT VALID checks before dropping only superseded
-- capacity checks; no historical data scan, body rewrite, RLS or ACL change.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='dashboard_report_artifacts'::regclass
          AND conname='dashboard_report_artifacts_body_representation_v2') THEN
        ALTER TABLE dashboard_report_artifacts
            ADD CONSTRAINT dashboard_report_artifacts_body_representation_v2 CHECK (
                (body_storage='inline' AND content IS NOT NULL
                 AND octet_length(content) BETWEEN 1 AND 2097152
                 AND source_capture IS NULL
                 AND (body_bytes IS NULL OR body_bytes=octet_length(content))
                 AND (body_digest IS NULL OR octet_length(body_digest)=32))
                OR
                (body_storage='chunks' AND content IS NULL
                 AND body_bytes IS NOT NULL AND body_bytes BETWEEN 1 AND 140737488355328
                 AND body_digest IS NOT NULL AND octet_length(body_digest)=32
                 AND source_capture IS NOT NULL AND jsonb_typeof(source_capture)='object'
                 AND source_capture @> '{"version":1}'::jsonb
                 AND source_capture->>'tenant_id' IS NOT NULL
                 AND source_capture->>'tenant_id'=tenant_id::text
                 AND octet_length(source_capture::text)<=1048576)
            ) NOT VALID;
    END IF;
END $$;
ALTER TABLE dashboard_report_artifacts
    DROP CONSTRAINT IF EXISTS dashboard_report_artifacts_body_representation;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='dashboard_report_artifact_chunks'::regclass
          AND conname='dashboard_report_artifact_chunks_ordinal_nonnegative') THEN
        ALTER TABLE dashboard_report_artifact_chunks
            ADD CONSTRAINT dashboard_report_artifact_chunks_ordinal_nonnegative
            CHECK (ordinal >= 0) NOT VALID;
    END IF;
END $$;
ALTER TABLE dashboard_report_artifact_chunks
    DROP CONSTRAINT IF EXISTS dashboard_report_artifact_chunks_ordinal_check;
