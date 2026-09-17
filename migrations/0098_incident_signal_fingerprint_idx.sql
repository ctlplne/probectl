-- 0098_incident_signal_fingerprint_idx.sql
-- DPR-078: one row per (incident, signal fingerprint); legacy rows with an
-- empty fingerprint are excluded so the index builds on any existing timeline.

-- probectl:no-tx: CREATE INDEX CONCURRENTLY is rejected inside a PostgreSQL transaction
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS incident_signals_fingerprint_uidx
    ON incident_signals (incident_id, fingerprint)
    WHERE fingerprint <> '';
