-- 0067_device_collection_outcomes.sql
-- Latest bounded, non-secret readiness receipt per explicitly configured
-- device target/protocol. This is operational state, not raw SNMP evidence.

CREATE TABLE IF NOT EXISTS device_collection_outcomes (
    tenant_id          uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id           text        NOT NULL,
    configured_target  text        NOT NULL,
    protocol            text        NOT NULL,
    last_attempt_at     timestamptz,
    last_success_at     timestamptz,
    state               text        NOT NULL,
    reason              text        NOT NULL,
    row_count           integer     NOT NULL DEFAULT 0,
    next_action         text        NOT NULL,
    updated_at          timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, agent_id, configured_target, protocol),
    CHECK (length(agent_id) BETWEEN 1 AND 128),
    CHECK (length(configured_target) BETWEEN 1 AND 255),
    CHECK (protocol IN ('lldp', 'cdp')),
    CHECK (state IN ('ok_with_rows', 'healthy_empty', 'unsupported', 'failed', 'never_observed')),
    CHECK (reason IN (
      'rows_observed', 'no_rows_observed', 'mib_unsupported', 'poll_failed',
      'credential_unavailable', 'transport_unreachable', 'base_poll_failed',
      'never_attempted'
    )),
    CHECK (next_action IN (
      'review_neighbor_evidence', 'review_target_neighbor_configuration',
      'enable_protocol_on_configured_target', 'verify_configured_target_access',
      'wait_for_first_collection'
    )),
    CHECK (row_count BETWEEN 0 AND 256),
    CHECK (
      (state = 'never_observed'
       AND last_attempt_at IS NULL
       AND last_success_at IS NULL
       AND row_count = 0)
      OR
      (state <> 'never_observed'
       AND last_attempt_at IS NOT NULL
       AND (last_success_at IS NULL OR last_success_at <= last_attempt_at))
    ),
    CHECK (
      (state = 'ok_with_rows' AND row_count > 0)
      OR
      (state <> 'ok_with_rows' AND row_count = 0)
    ),
    CHECK (
      (state = 'ok_with_rows'
       AND reason = 'rows_observed'
       AND next_action = 'review_neighbor_evidence'
       AND last_success_at IS NOT NULL)
      OR
      (state = 'healthy_empty'
       AND reason = 'no_rows_observed'
       AND next_action = 'review_target_neighbor_configuration'
       AND last_success_at IS NOT NULL)
      OR
      (state = 'unsupported'
       AND reason = 'mib_unsupported'
       AND next_action = 'enable_protocol_on_configured_target')
      OR
      (state = 'failed'
       AND reason IN (
         'poll_failed', 'credential_unavailable', 'transport_unreachable',
         'base_poll_failed'
       )
       AND next_action = 'verify_configured_target_access')
      OR
      (state = 'never_observed'
       AND reason = 'never_attempted'
       AND next_action = 'wait_for_first_collection')
    )
);

CREATE INDEX IF NOT EXISTS device_collection_outcomes_tenant_attempt_idx
    ON device_collection_outcomes
       (tenant_id, last_attempt_at DESC NULLS LAST, agent_id, configured_target, protocol);

ALTER TABLE device_collection_outcomes ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_collection_outcomes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON device_collection_outcomes;
CREATE POLICY tenant_isolation ON device_collection_outcomes
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON device_collection_outcomes TO probectl_app;
