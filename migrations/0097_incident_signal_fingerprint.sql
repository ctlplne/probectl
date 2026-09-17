-- 0097_incident_signal_fingerprint.sql
-- DPR-078: the incident timeline accepted the same signal again and again —
-- the bus is at-least-once and the BGP analyzer re-runs, so the lab's first
-- routing incident held 20,389 signals of which 18,020 were byte-identical
-- copies (same kind, occurrence time and attributes). Every signal now carries
-- a content fingerprint; 0098 adds the unique index that makes a duplicate
-- inside the same incident a no-op. Legacy rows keep an empty fingerprint and
-- never conflict (expand only).
ALTER TABLE incident_signals ADD COLUMN IF NOT EXISTS fingerprint text NOT NULL DEFAULT '';
