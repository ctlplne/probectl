-- 0065_alert_evaluation_receipts.sql
-- A deliberately small, tenant-local transition ledger for alert explanation.
-- This is not a general event/log table: the writer enforces a seven-day
-- expiry, 64 receipts per series, and 256 receipts per rule on every append.

CREATE TABLE IF NOT EXISTS alert_evaluation_receipts (
    tenant_id          uuid             NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id            uuid             NOT NULL,
    fingerprint        text             NOT NULL,
    contract_version   text             NOT NULL,
    rule_revision      text             NOT NULL,
    evaluation_state   text             NOT NULL,
    observed_at        timestamptz      NOT NULL,
    observed_value     double precision,
    expectation_kind   text             NOT NULL,
    comparison         text             NOT NULL DEFAULT '',
    threshold          double precision,
    expected_mean      double precision,
    expected_stddev    double precision,
    expected_lower     double precision,
    expected_upper     double precision,
    breach_count       integer          NOT NULL DEFAULT 0,
    required_breaches  integer          NOT NULL DEFAULT 1,
    warmup_samples     integer          NOT NULL DEFAULT 0,
    warmup_required    integer          NOT NULL DEFAULT 0,
    reason             text             NOT NULL DEFAULT '',
    labels             jsonb            NOT NULL DEFAULT '{}',
    expires_at         timestamptz      NOT NULL,
    PRIMARY KEY (tenant_id, rule_id, fingerprint, observed_at, evaluation_state),
    CHECK (contract_version = 'probectl.alert-evaluation/v1'),
    CHECK (evaluation_state IN ('no_data', 'warming', 'normal', 'pending', 'firing', 'steady', 'resolved')),
    CHECK (expectation_kind IN ('threshold', 'baseline')),
    CHECK (length(fingerprint) BETWEEN 1 AND 2048),
    CHECK (length(rule_revision) BETWEEN 1 AND 64),
    CHECK (length(reason) <= 500),
    CHECK (breach_count >= 0 AND required_breaches >= 1),
    CHECK (warmup_samples >= 0 AND warmup_required >= 0),
    CHECK (jsonb_typeof(labels) = 'object'),
    CHECK (octet_length(labels::text) <= 8192),
    CHECK (expires_at > observed_at)
);

CREATE INDEX IF NOT EXISTS alert_evaluation_receipts_tenant_rule_time_idx
    ON alert_evaluation_receipts (tenant_id, rule_id, observed_at DESC);

ALTER TABLE alert_evaluation_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_evaluation_receipts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON alert_evaluation_receipts;
CREATE POLICY tenant_isolation ON alert_evaluation_receipts
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON alert_evaluation_receipts TO probectl_app;
