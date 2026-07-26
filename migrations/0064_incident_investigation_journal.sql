-- 0064_incident_investigation_journal.sql
-- Tenant-local, inert incident investigation notes and cited checkpoints.
-- A checkpoint stores only an authenticated share/evidence reference. The
-- control plane re-authorizes that live share before returning evidence
-- details; expired, revoked, missing, and cross-tenant references fail closed.
-- probectl:no-tx: the tenant-qualified incident index is built CONCURRENTLY so
-- live incident ingestion is not stalled during an upgrade.

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS incidents_tenant_id_id_uidx
    ON incidents (tenant_id, id);

CREATE TABLE IF NOT EXISTS incident_journal_entries (
    tenant_id           uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                  text        NOT NULL,
    incident_id         uuid        NOT NULL,
    entry_kind          text        NOT NULL,
    body                text        NOT NULL,
    citation_share_id   text,
    citation_evidence_id text,
    created_by          text        NOT NULL DEFAULT '',
    created_at          timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT incident_journal_incident_fk
      FOREIGN KEY (tenant_id, incident_id)
      REFERENCES incidents (tenant_id, id) ON DELETE CASCADE,
    CHECK (entry_kind IN ('note', 'checkpoint')),
    CHECK (length(body) BETWEEN 1 AND 4000),
    CHECK (expires_at > created_at),
    CHECK (
      (entry_kind = 'note' AND citation_share_id IS NULL AND citation_evidence_id IS NULL)
      OR
      (entry_kind = 'checkpoint' AND citation_share_id IS NOT NULL AND citation_evidence_id IS NOT NULL)
    )
);

CREATE INDEX IF NOT EXISTS incident_journal_tenant_incident_created_idx
    ON incident_journal_entries (tenant_id, incident_id, created_at, id);

CREATE INDEX IF NOT EXISTS incident_journal_tenant_expiry_idx
    ON incident_journal_entries (tenant_id, expires_at);

ALTER TABLE incident_journal_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE incident_journal_entries FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON incident_journal_entries;
CREATE POLICY tenant_isolation ON incident_journal_entries
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON incident_journal_entries TO probectl_app;
