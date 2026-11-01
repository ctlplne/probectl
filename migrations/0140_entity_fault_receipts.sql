-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-2: an mTLS fault observation is admitted once, even after its incident
-- is resolved. Receipt claim and incident correlation share the tenant's
-- advisory-locked transaction; a failed correlation rolls the claim back.
CREATE TABLE IF NOT EXISTS entity_fault_receipts (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id text NOT NULL CHECK (octet_length(agent_id) BETWEEN 1 AND 128),
    observation_id uuid NOT NULL,
    source_kind text NOT NULL CHECK (source_kind IN
        ('device_target', 'flow_exporter')),
    source_ref text NOT NULL CHECK (octet_length(source_ref) BETWEEN 1 AND 1024),
    payload_fingerprint text NOT NULL CHECK (length(payload_fingerprint) = 64),
    incident_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, agent_id, observation_id),
    FOREIGN KEY (tenant_id, incident_id)
        REFERENCES incidents(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS entity_fault_receipts_tenant_incident_idx
    ON entity_fault_receipts (tenant_id, incident_id)
    WHERE incident_id IS NOT NULL;

ALTER TABLE entity_fault_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE entity_fault_receipts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON entity_fault_receipts;
CREATE POLICY tenant_isolation ON entity_fault_receipts
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
GRANT SELECT, INSERT, UPDATE, DELETE ON entity_fault_receipts TO probectl_app;

DO $entity_fault_receipts_write_fence$
BEGIN
    DROP TRIGGER IF EXISTS tenant_write_fence ON public.entity_fault_receipts;
    CREATE TRIGGER tenant_write_fence
        BEFORE INSERT OR UPDATE ON public.entity_fault_receipts
        FOR EACH ROW
        EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
    ALTER TABLE public.entity_fault_receipts
        ENABLE ALWAYS TRIGGER tenant_write_fence;
END
$entity_fault_receipts_write_fence$;
