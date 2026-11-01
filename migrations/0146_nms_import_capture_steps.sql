-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-2b: one completed, bounded source endpoint per receipt. A retry of an
-- incomplete endpoint replays page hashes; a second read verifies the same
-- page range. No vendor body, URL, credential or group name is stored here.

CREATE TABLE IF NOT EXISTS nms_import_capture_steps (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    resource_kind text NOT NULL CHECK
        (resource_kind IN ('devices', 'locations', 'groups', 'memberships', 'rules')),
    group_external_id text NOT NULL DEFAULT '' CHECK
        (group_external_id = '' OR
         (group_external_id ~ '^[1-9][0-9]*$' AND octet_length(group_external_id) <= 20)),
    start_page bigint NOT NULL CHECK (start_page >= 0),
    end_page bigint NOT NULL CHECK (end_page > start_page),
    start_row bigint NOT NULL CHECK (start_row >= 0),
    end_row bigint NOT NULL CHECK (end_row >= start_row),
    completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    verified_at timestamptz,
    PRIMARY KEY (tenant_id, context_id, plan_id, resource_kind, group_external_id),
    FOREIGN KEY (tenant_id, context_id, plan_id)
        REFERENCES nms_import_plans(tenant_id, context_id, id) ON DELETE CASCADE,
    CHECK ((resource_kind = 'memberships') = (group_external_id <> ''))
);
CREATE INDEX IF NOT EXISTS nms_import_capture_steps_tenant_page_idx
    ON nms_import_capture_steps(tenant_id, context_id, plan_id, start_page);

ALTER TABLE nms_import_capture_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE nms_import_capture_steps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON nms_import_capture_steps;
CREATE POLICY tenant_isolation ON nms_import_capture_steps
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP TRIGGER IF EXISTS tenant_write_fence ON nms_import_capture_steps;
CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON nms_import_capture_steps
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE nms_import_capture_steps ENABLE ALWAYS TRIGGER tenant_write_fence;
GRANT SELECT, INSERT, UPDATE, DELETE ON nms_import_capture_steps TO probectl_app;
