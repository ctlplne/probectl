-- 0011_alert_rules.sql
-- Alert rules (S16, F8). A new tenant-owned table: tenant_id + Row-Level Security
-- confine every row to its tenant (F50), so the /v1/alerts CRUD API can never read
-- or write across tenants. Idempotent (IF NOT EXISTS) for safe re-runs.
--
-- The webhook secret inside channels is sensitive; it is redacted from API
-- responses. (A follow-up envelope-encrypts channel secrets at rest — guardrail 6.)

CREATE TABLE IF NOT EXISTS alert_rules (
    id               uuid             PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid             NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name             text             NOT NULL,
    enabled          boolean          NOT NULL DEFAULT true,
    metric           text             NOT NULL,
    match_labels     jsonb            NOT NULL DEFAULT '{}',
    type             text             NOT NULL,
    comparison       text             NOT NULL DEFAULT '',
    threshold        double precision NOT NULL DEFAULT 0,
    window_n         integer          NOT NULL DEFAULT 0,
    sensitivity      double precision NOT NULL DEFAULT 0,
    for_n            integer          NOT NULL DEFAULT 0,
    renotify_seconds integer          NOT NULL DEFAULT 0,
    severity         text             NOT NULL DEFAULT 'warning',
    channels         jsonb            NOT NULL DEFAULT '[]',
    created_at       timestamptz      NOT NULL DEFAULT now(),
    updated_at       timestamptz      NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS alert_rules_tenant_idx ON alert_rules (tenant_id);
-- Rule names are unique within a tenant (409 on a duplicate); two tenants may reuse a name.
CREATE UNIQUE INDEX IF NOT EXISTS alert_rules_tenant_name_idx ON alert_rules (tenant_id, name);

ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rules FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON alert_rules;
CREATE POLICY tenant_isolation ON alert_rules
    USING (tenant_id = NULLIF(current_setting('netctl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('netctl.tenant_id', true), '')::uuid);

-- netctl_app inherits DML on new public tables via ALTER DEFAULT PRIVILEGES (0007),
-- but grant explicitly so the table is reachable regardless of creation role.
GRANT SELECT, INSERT, UPDATE, DELETE ON alert_rules TO netctl_app;
