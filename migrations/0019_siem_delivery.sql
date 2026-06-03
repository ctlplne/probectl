-- 0019_siem_delivery.sql
-- SIEM export (S32, F26): a per-tenant cursor recording the highest audit `seq`
-- already forwarded to the operator's SIEM. The audit poller resumes from this
-- cursor after a restart, so events are neither dropped nor (modulo a crash
-- window) re-sent — delivery is idempotent on the SIEM side regardless. There is
-- no payload here: telemetry never lands in a netctl table for export; the
-- forwarder streams audit + threat signals straight out.
-- RLS confines each row to its tenant (F50). Idempotent + additive.

CREATE TABLE IF NOT EXISTS siem_delivery (
    tenant_id  uuid        PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    last_seq   bigint      NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

DO $$
BEGIN
    EXECUTE 'ALTER TABLE siem_delivery ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE siem_delivery FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON siem_delivery';
    EXECUTE $pol$
        CREATE POLICY tenant_isolation ON siem_delivery
          USING (tenant_id = NULLIF(current_setting('netctl.tenant_id', true), '')::uuid)
          WITH CHECK (tenant_id = NULLIF(current_setting('netctl.tenant_id', true), '')::uuid)
    $pol$;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON siem_delivery TO netctl_app;
