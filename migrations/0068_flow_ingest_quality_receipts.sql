-- 0068_flow_ingest_quality_receipts.sql
-- Latest bounded, secret-free quality receipt per ACL-accepted flow exporter
-- and protocol. This operational state never stores raw datagrams/flow fields.

CREATE TABLE IF NOT EXISTS flow_ingest_quality_receipts (
    tenant_id              uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id               text        NOT NULL,
    exporter_address       inet        NOT NULL,
    protocol               text        NOT NULL,
    window_started_at      timestamptz NOT NULL,
    window_ended_at        timestamptz NOT NULL,
    last_packet_at         timestamptz NOT NULL,
    last_valid_record_at   timestamptz,
    packets_received       bigint      NOT NULL DEFAULT 0,
    records_decoded        bigint      NOT NULL DEFAULT 0,
    decode_error_packets   bigint      NOT NULL DEFAULT 0,
    template_misses        bigint      NOT NULL DEFAULT 0,
    queue_dropped_records  bigint      NOT NULL DEFAULT 0,
    emit_dropped_records   bigint      NOT NULL DEFAULT 0,
    template_state         text        NOT NULL,
    sampling_state         text        NOT NULL,
    state                  text        NOT NULL,
    reason                 text        NOT NULL,
    next_action            text        NOT NULL,
    updated_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, agent_id, exporter_address, protocol),
    CHECK (length(agent_id) BETWEEN 1 AND 128),
    CHECK (protocol IN ('netflow', 'netflow5', 'netflow9', 'ipfix', 'sflow5')),
    CHECK (window_started_at <= window_ended_at),
    CHECK (last_packet_at <= window_ended_at),
    CHECK (last_valid_record_at IS NULL OR last_valid_record_at <= last_packet_at),
    CHECK (records_decoded = 0 OR last_valid_record_at IS NOT NULL),
    CHECK (
      packets_received >= 0 AND records_decoded >= 0
      AND decode_error_packets >= 0 AND template_misses >= 0
      AND queue_dropped_records >= 0 AND emit_dropped_records >= 0
    ),
    CHECK (template_state IN ('not_applicable', 'unknown', 'learning', 'ready', 'missing')),
    CHECK (sampling_state IN ('unknown', 'unsampled', 'sampled', 'mixed')),
    CHECK (state IN ('healthy', 'degraded', 'stale')),
    CHECK (
      (state = 'stale'
       AND window_ended_at - last_packet_at > interval '3 minutes')
      OR
      (state <> 'stale'
       AND window_ended_at - last_packet_at <= interval '3 minutes')
    ),
    CHECK (reason IN (
      'receiving_valid_records', 'waiting_for_templates', 'template_missing',
      'decode_errors', 'queue_loss', 'emit_loss', 'no_valid_records',
      'no_recent_packets'
    )),
    CHECK (next_action IN (
      'continue_monitoring', 'verify_exporter_templates',
      'verify_exporter_protocol', 'reduce_local_ingest_pressure',
      'verify_local_bus_delivery', 'verify_exporter_delivery'
    )),
    CHECK (
      (protocol IN ('netflow5', 'sflow5') AND template_state = 'not_applicable')
      OR
      (protocol IN ('netflow9', 'ipfix') AND template_state IN ('learning', 'ready', 'missing'))
      OR
      (protocol = 'netflow' AND template_state = 'unknown')
    ),
    CHECK (
      (state = 'healthy'
       AND reason = 'receiving_valid_records'
       AND next_action = 'continue_monitoring'
       AND last_valid_record_at IS NOT NULL
       AND decode_error_packets = 0 AND template_misses = 0
       AND queue_dropped_records = 0 AND emit_dropped_records = 0
       AND template_state <> 'missing')
      OR
      (state = 'degraded'
       AND (
         (reason IN ('waiting_for_templates', 'template_missing')
          AND next_action = 'verify_exporter_templates'
          AND emit_dropped_records = 0 AND queue_dropped_records = 0
          AND decode_error_packets = 0
          AND (
            (reason = 'waiting_for_templates'
             AND last_valid_record_at IS NULL
             AND template_state = 'learning'
             AND template_misses = 0)
            OR
            (reason = 'template_missing'
             AND (template_misses > 0 OR template_state = 'missing'))
          ))
         OR
         (reason IN ('decode_errors', 'no_valid_records')
          AND next_action = 'verify_exporter_protocol'
          AND emit_dropped_records = 0 AND queue_dropped_records = 0
          AND (
            (reason = 'decode_errors' AND decode_error_packets > 0)
            OR
            (reason = 'no_valid_records'
             AND decode_error_packets = 0
             AND template_misses = 0
             AND last_valid_record_at IS NULL
             AND template_state NOT IN ('learning', 'missing'))
          ))
         OR
         (reason = 'queue_loss'
          AND next_action = 'reduce_local_ingest_pressure'
          AND emit_dropped_records = 0 AND queue_dropped_records > 0)
         OR
         (reason = 'emit_loss'
          AND next_action = 'verify_local_bus_delivery'
          AND emit_dropped_records > 0)
       ))
      OR
      (state = 'stale'
       AND reason = 'no_recent_packets'
       AND next_action = 'verify_exporter_delivery')
    )
);

CREATE INDEX IF NOT EXISTS flow_ingest_quality_receipts_tenant_window_idx
    ON flow_ingest_quality_receipts
       (tenant_id, window_ended_at DESC, agent_id, exporter_address, protocol);

ALTER TABLE flow_ingest_quality_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_ingest_quality_receipts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON flow_ingest_quality_receipts;
CREATE POLICY tenant_isolation ON flow_ingest_quality_receipts
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON flow_ingest_quality_receipts TO probectl_app;
