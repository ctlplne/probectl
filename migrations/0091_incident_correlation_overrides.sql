-- 0091_incident_correlation_overrides.sql
-- Durable, tenant-scoped, reversible human overrides for false incident
-- grouping. Original evidence is retained; an override creates an independent
-- incident and excludes future matching signals from the named source incident
-- until explicit reversal.
-- probectl:no-tx: the pre-existing incident_signals index must be built concurrently

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS incident_signals_tenant_id_id_uidx
    ON incident_signals (tenant_id, id);

CREATE TABLE IF NOT EXISTS incident_correlation_overrides (
    id                   uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id            uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_incident_id   uuid        NOT NULL,
    detached_incident_id uuid        NOT NULL,
    source_signal_id     uuid        NOT NULL,
    plane                text        NOT NULL,
    kind                 text        NOT NULL,
    target               text        NOT NULL DEFAULT '',
    prefix               text        NOT NULL DEFAULT '',
    reason               text        NOT NULL,
    active               boolean     NOT NULL DEFAULT true,
    created_by           text        NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    reversed_by          text        NOT NULL DEFAULT '',
    reversal_reason      text        NOT NULL DEFAULT '',
    reversed_at          timestamptz,
    CONSTRAINT incident_correlation_overrides_source_fk
      FOREIGN KEY (tenant_id, source_incident_id)
      REFERENCES incidents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT incident_correlation_overrides_detached_fk
      FOREIGN KEY (tenant_id, detached_incident_id)
      REFERENCES incidents (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT incident_correlation_overrides_signal_fk
      FOREIGN KEY (tenant_id, source_signal_id)
      REFERENCES incident_signals (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT incident_correlation_overrides_reason_nonempty
      CHECK (length(btrim(reason)) > 0),
    CONSTRAINT incident_correlation_overrides_reversal_consistent
      CHECK (
        (active AND reversed_at IS NULL AND reversed_by = '' AND reversal_reason = '')
        OR
        (NOT active AND reversed_at IS NOT NULL AND reversed_by <> '' AND reversal_reason <> '')
      )
);

CREATE INDEX IF NOT EXISTS incident_correlation_overrides_tenant_source_idx
    ON incident_correlation_overrides (tenant_id, source_incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS incident_correlation_overrides_active_match_idx
    ON incident_correlation_overrides (tenant_id, plane, kind, target, prefix)
    WHERE active;
CREATE UNIQUE INDEX IF NOT EXISTS incident_correlation_overrides_one_active_match_uidx
    ON incident_correlation_overrides (tenant_id, source_incident_id, plane, kind, target, prefix)
    WHERE active;

ALTER TABLE incident_correlation_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_correlation_overrides FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON incident_correlation_overrides;
CREATE POLICY tenant_isolation ON incident_correlation_overrides
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON incident_correlation_overrides TO probectl_app;
