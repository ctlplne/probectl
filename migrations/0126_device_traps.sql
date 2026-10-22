-- 0126_device_traps.sql
-- D-60 / DPR-296: the control plane's SNMP trap read model. The device agent
-- authenticates each trap (SNMPv2c community / SNMPv3 USM) and publishes it on
-- the tenant's probectl.<lane>.device.trap-events lane; until now nothing in
-- the control plane consumed that lane, so an accepted trap stopped there.
-- The trap consumer persists each one here and GET /v1/device/traps reads it.
--
-- Tenant isolation is the database's (G7-1): tenant_id is non-null from this,
-- the table's first migration, FORCE ROW LEVEL SECURITY binds every read and
-- write to the transaction's probectl.tenant_id, and the generic tenant write
-- fence (0086) refuses writes from an erased or suspended tenant. Siloed
-- tenants get their own copy through the silo provisioner (it copies every
-- public tenant_id table); hybrid tenants keep control state pooled here.
--
-- Idempotent on redelivery: the agent's dedup fingerprint is unique per
-- (tenant, agent), so a redelivered bus record inserts nothing. Bounded: the
-- writer prunes rows older than 30 days and keeps at most 10,000 per tenant
-- (internal/device TrapRetention / MaxTrapsPerTenant). No credential material
-- is stored: auth_principal is the configured source name or USM user name.

CREATE TABLE IF NOT EXISTS device_traps (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id           text        NOT NULL,
    fingerprint        text        NOT NULL,
    device_address     text        NOT NULL,
    source_address     text        NOT NULL DEFAULT '',
    auth_principal     text        NOT NULL DEFAULT '',
    version            text        NOT NULL,
    kind               text        NOT NULL,
    severity           text        NOT NULL,
    trap_oid           text        NOT NULL DEFAULT '',
    request_id         bigint      NOT NULL DEFAULT 0,
    uptime_ticks       bigint      NOT NULL DEFAULT 0,
    if_index           bigint      NOT NULL DEFAULT 0,
    varbinds           jsonb       NOT NULL DEFAULT '[]',
    varbinds_truncated boolean     NOT NULL DEFAULT false,
    observed_at        timestamptz NOT NULL,
    received_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, agent_id, fingerprint),
    CHECK (length(agent_id) BETWEEN 1 AND 128),
    CHECK (length(fingerprint) BETWEEN 1 AND 64),
    CHECK (length(device_address) BETWEEN 1 AND 255),
    CHECK (length(source_address) <= 255),
    CHECK (length(auth_principal) <= 255),
    CHECK (version IN ('snmpv1', 'snmpv2c', 'snmpv3')),
    CHECK (length(kind) BETWEEN 1 AND 64),
    CHECK (severity IN ('info', 'warning', 'critical')),
    CHECK (length(trap_oid) <= 255),
    CHECK (uptime_ticks BETWEEN 0 AND 4294967295),
    CHECK (if_index BETWEEN 0 AND 4294967295),
    CHECK (jsonb_typeof(varbinds) = 'array' AND jsonb_array_length(varbinds) <= 64)
);

CREATE INDEX IF NOT EXISTS device_traps_tenant_received_idx
    ON device_traps (tenant_id, received_at DESC, id);
CREATE INDEX IF NOT EXISTS device_traps_tenant_device_received_idx
    ON device_traps (tenant_id, device_address, received_at DESC);
CREATE INDEX IF NOT EXISTS device_traps_tenant_oid_received_idx
    ON device_traps (tenant_id, trap_oid, received_at DESC);

ALTER TABLE device_traps ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_traps FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON device_traps;
CREATE POLICY tenant_isolation ON device_traps
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON device_traps TO probectl_app;

-- The generic tenant write fence (0086), installed from the table's first
-- migration so no backfill is ever needed (0113/0117 were exactly that).
DO $device_traps_write_fence$
BEGIN
    DROP TRIGGER IF EXISTS tenant_write_fence ON public.device_traps;
    CREATE TRIGGER tenant_write_fence
        BEFORE INSERT OR UPDATE ON public.device_traps
        FOR EACH ROW
        EXECUTE FUNCTION
            public.probectl_enforce_tenant_write_fence();
    ALTER TABLE public.device_traps
        ENABLE ALWAYS TRIGGER tenant_write_fence;
END
$device_traps_write_fence$;
