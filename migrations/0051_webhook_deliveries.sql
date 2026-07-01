-- 0051_webhook_deliveries.sql
-- Change webhooks (S29, F39): a tenant-scoped idempotency ledger for signed
-- inbound deliveries. The control plane claims a delivery here before writing
-- change_events or audit_events, so replaying the same provider delivery UUID is
-- an idempotent success instead of a duplicate mutation. No webhook payload is
-- stored in this table.

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    tenant_id       uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    credential_id   text        NOT NULL,
    provider        text        NOT NULL,
    delivery_id     text        NOT NULL,
    event_count     integer     NOT NULL DEFAULT 0 CHECK (event_count >= 0),
    duplicate_count integer     NOT NULL DEFAULT 0 CHECK (duplicate_count >= 0),
    first_seen_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, credential_id, provider, delivery_id)
);

CREATE INDEX IF NOT EXISTS webhook_deliveries_tenant_seen_idx
    ON webhook_deliveries (tenant_id, first_seen_at DESC);

DO $$
BEGIN
    EXECUTE 'ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE webhook_deliveries FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON webhook_deliveries';
    EXECUTE $pol$
        CREATE POLICY tenant_isolation ON webhook_deliveries
          USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
          WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    $pol$;
END $$;

GRANT SELECT, INSERT, UPDATE ON webhook_deliveries TO probectl_app;
