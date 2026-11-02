-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- A finite, reviewed source rule may create only a disabled native alert.
-- This table records its source identity and the exact operator-owned target
-- that was checked in the write transaction; it stores no source SQL,
-- notification operation, channel or credential.
-- lock-ok: alert_rules is an operator-scale configuration table with one row
-- per human-authored rule, never a telemetry ingestion table. The short index
-- lock cannot stall event ingestion; this key lets the tenant-qualified FK
-- reject a cross-tenant alert binding at the storage boundary.
CREATE UNIQUE INDEX IF NOT EXISTS alert_rules_tenant_id_id_idx
    ON alert_rules(tenant_id,id);

CREATE TABLE IF NOT EXISTS nms_import_alert_bindings (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    rule_external_id text NOT NULL
        CHECK (rule_external_id ~ '^[1-9][0-9]*$' AND octet_length(rule_external_id) <= 20),
    device_kind text NOT NULL DEFAULT 'device' CHECK (device_kind='device'),
    device_external_id text NOT NULL
        CHECK (octet_length(device_external_id) BETWEEN 1 AND 256),
    row_kind text NOT NULL DEFAULT 'alert_rule' CHECK (row_kind='alert_rule'),
    agent_id text NOT NULL
        CHECK (octet_length(agent_id) BETWEEN 1 AND 128 AND agent_id !~ '[[:cntrl:]]'),
    target_address text NOT NULL
        CHECK (octet_length(target_address) BETWEEN 1 AND 255
               AND target_address !~ '[[:cntrl:]]'),
    plan_id uuid NOT NULL,
    alert_rule_id uuid NOT NULL,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,context_id,source_id,rule_external_id),
    UNIQUE (tenant_id,alert_rule_id),
    FOREIGN KEY (tenant_id,context_id,source_id,device_kind,device_external_id)
        REFERENCES nms_import_provenance
            (tenant_id,context_id,source_id,object_kind,external_id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,context_id,plan_id,source_id)
        REFERENCES nms_import_plans(tenant_id,context_id,id,source_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id,context_id,plan_id,row_kind,rule_external_id)
        REFERENCES nms_import_rows
            (tenant_id,context_id,plan_id,object_kind,external_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id,alert_rule_id)
        REFERENCES alert_rules(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS nms_import_alert_bindings_plan_idx
    ON nms_import_alert_bindings(tenant_id,context_id,plan_id);
CREATE INDEX IF NOT EXISTS nms_import_alert_bindings_device_idx
    ON nms_import_alert_bindings
        (tenant_id,context_id,source_id,device_external_id);

ALTER TABLE nms_import_alert_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE nms_import_alert_bindings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON nms_import_alert_bindings;
CREATE POLICY tenant_isolation ON nms_import_alert_bindings
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);
DROP TRIGGER IF EXISTS tenant_write_fence ON nms_import_alert_bindings;
CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE
    ON nms_import_alert_bindings FOR EACH ROW
    EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE nms_import_alert_bindings ENABLE ALWAYS TRIGGER tenant_write_fence;
GRANT SELECT,INSERT,UPDATE,DELETE ON nms_import_alert_bindings TO probectl_app;
