-- 0118_webhook_delivery_body_fingerprint.sql
-- AUTHZ-19: replay protection that survives a rotated delivery-id header. The
-- change-webhook receiver deduplicated on the client-supplied provider delivery
-- id (X-GitHub-Delivery / X-Gitlab-Event-UUID / the generic delivery header), so
-- resending the SAME signed body under a NEW delivery id was accepted again and
-- appended a second change event. We add a server-computed fingerprint of the
-- exact authenticated body (the bytes the HMAC signs), scoped per
-- (tenant, credential, provider), so a replayed authenticated body is an
-- idempotent no-op no matter what delivery-id header the client supplies. The
-- existing delivery-id idempotency (the table primary key) is kept as well.
--
-- Nullable by design: rows written before this column existed predate the
-- fingerprint and keep their delivery-id idempotency; only new deliveries carry
-- a fingerprint, so the partial unique index is restricted to non-null values.

ALTER TABLE webhook_deliveries ADD COLUMN IF NOT EXISTS body_fingerprint text;

-- One row per (tenant, credential, provider, authenticated-body fingerprint);
-- the partial index also makes a concurrent double-submit of the same body fail
-- closed instead of storing a second row.
-- lock-ok: webhook_deliveries is an operator-scale idempotency ledger (bounded
-- by inbound signed-webhook volume from CI/CD and ITSM integrations), not a hot
-- telemetry table.
CREATE UNIQUE INDEX IF NOT EXISTS webhook_deliveries_body_fp_key
    ON webhook_deliveries (tenant_id, credential_id, provider, body_fingerprint)
    WHERE body_fingerprint IS NOT NULL;
