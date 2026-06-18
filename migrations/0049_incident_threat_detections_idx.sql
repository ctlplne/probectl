-- 0049_incident_threat_detections_idx.sql
-- Recent threat detections are served from the durable incident timeline in HA
-- mode. Keep the query tenant-scoped and newest-first without scanning every
-- historical incident signal.

-- probectl:no-tx: CREATE INDEX CONCURRENTLY is rejected inside a PostgreSQL transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS incident_signals_threat_detections_idx
    ON incident_signals (tenant_id, occurred_at DESC)
    WHERE plane = 'threat'
      AND (attributes ? 'intel.source' OR attributes ? 'detector.rule');
