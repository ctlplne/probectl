-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-2b: a reviewed Zabbix SNMP cadence is an inert, source-keyed proposal.
-- An operator supplies a separate device credential reference when exporting
-- an agent config. Neither this table nor import rows store that reference.
CREATE TABLE IF NOT EXISTS nms_import_poll_proposals (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    host_kind text NOT NULL DEFAULT 'device' CHECK (host_kind='device'),
    host_external_id text NOT NULL
        CHECK (octet_length(host_external_id) BETWEEN 1 AND 256
               AND host_external_id !~ '[[:cntrl:]]'),
    object_kind text NOT NULL DEFAULT 'poll_setting' CHECK (object_kind='poll_setting'),
    item_external_id text NOT NULL
        CHECK (octet_length(item_external_id) BETWEEN 1 AND 256
               AND item_external_id !~ '[[:cntrl:]]'),
    poll_seconds bigint NOT NULL CHECK (poll_seconds BETWEEN 15 AND 86400),
    plan_id uuid NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision>0),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,context_id,source_id,item_external_id),
    FOREIGN KEY (tenant_id,context_id,source_id,host_kind,host_external_id)
        REFERENCES nms_import_provenance
            (tenant_id,context_id,source_id,object_kind,external_id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,context_id,plan_id,source_id)
        REFERENCES nms_import_plans(tenant_id,context_id,id,source_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id,context_id,plan_id,object_kind,item_external_id)
        REFERENCES nms_import_rows
            (tenant_id,context_id,plan_id,object_kind,external_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX IF NOT EXISTS nms_import_poll_proposals_host_idx
    ON nms_import_poll_proposals(tenant_id,context_id,source_id,host_external_id);
CREATE INDEX IF NOT EXISTS nms_import_poll_proposals_plan_idx
    ON nms_import_poll_proposals(tenant_id,context_id,plan_id);

ALTER TABLE nms_import_poll_proposals ENABLE ROW LEVEL SECURITY;
ALTER TABLE nms_import_poll_proposals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON nms_import_poll_proposals;
CREATE POLICY tenant_isolation ON nms_import_poll_proposals
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);
DROP TRIGGER IF EXISTS tenant_write_fence ON nms_import_poll_proposals;
CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE
    ON nms_import_poll_proposals FOR EACH ROW
    EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE nms_import_poll_proposals ENABLE ALWAYS TRIGGER tenant_write_fence;
GRANT SELECT,INSERT,UPDATE,DELETE ON nms_import_poll_proposals TO probectl_app;
