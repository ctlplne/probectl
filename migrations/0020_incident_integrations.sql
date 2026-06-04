-- 0020_incident_integrations.sql
-- On-call + ITSM integration (S33, F27): the incident↔external mapping. Each row
-- links one incident to one connector (pagerduty/opsgenie/slack/teams/servicenow/
-- jira) and stores the external reference (ticket id / page dedup key) returned
-- when the object was opened. Two jobs:
--   * idempotency — a UNIQUE (tenant_id, incident_id, connector) means an incident
--     is opened at most once per connector, so a retry or a control-plane restart
--     never double-pages or duplicates a ticket;
--   * reverse lookup — an inbound webhook (ServiceNow/Jira "resolved") maps an
--     external_ref back to its incident to sync status the other way.
-- RLS confines every row to its tenant (F50). Idempotent + additive.

CREATE TABLE IF NOT EXISTS incident_integrations (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    incident_id  uuid        NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    connector    text        NOT NULL,
    external_ref text        NOT NULL DEFAULT '',
    status       text        NOT NULL DEFAULT 'open',
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, incident_id, connector)
);
CREATE INDEX IF NOT EXISTS incident_integrations_incident_idx
    ON incident_integrations (tenant_id, incident_id);
-- The inbound reverse lookup (connector + external_ref → incident).
CREATE INDEX IF NOT EXISTS incident_integrations_ref_idx
    ON incident_integrations (tenant_id, connector, external_ref);

DO $$
BEGIN
    EXECUTE 'ALTER TABLE incident_integrations ENABLE ROW LEVEL SECURITY';
    EXECUTE 'ALTER TABLE incident_integrations FORCE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS tenant_isolation ON incident_integrations';
    EXECUTE $pol$
        CREATE POLICY tenant_isolation ON incident_integrations
          USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
          WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    $pol$;
END $$;

GRANT SELECT, INSERT, UPDATE, DELETE ON incident_integrations TO probectl_app;
