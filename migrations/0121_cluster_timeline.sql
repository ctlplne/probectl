-- 0121_cluster_timeline.sql — PLAT-19: automatic (Postgres-native) promotion
-- signal for the split-brain fence.
--
-- The writer fence used only cluster_state.writer_epoch, which is bumped ONLY
-- by the SQL function cluster_promote() — a manual runbook step. If an operator
-- (or an orchestrator like Patroni / a managed failover) promotes a standby but
-- skips cluster_promote(), the new primary and the old ex-primary carry the
-- SAME epoch, so a writer endpoint still pointing at the ex-primary is not
-- fenced → split-brain writes that are later lost.
--
-- A real Postgres failover advances the WAL TIMELINE automatically, with no
-- human step, and the standby that followed the true primary replays onto the
-- new timeline. Expose that timeline id privilege-safely (pg_control_checkpoint
-- is restricted to pg_monitor by default) so the prober can read it and the
-- fence marks an ex-primary on the old timeline stale even before — or without —
-- the epoch bump. The epoch path stays as the operator-confirmed signal.
--
-- Idempotent + expand-only (CLAUDE.md §6): CREATE OR REPLACE + GRANT.

CREATE OR REPLACE FUNCTION cluster_timeline()
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
AS $$
    SELECT timeline_id::bigint FROM pg_control_checkpoint()
$$;

COMMENT ON FUNCTION cluster_timeline() IS
    'WAL timeline id for the split-brain fence (PLAT-19); advances automatically on a Postgres failover.';

GRANT EXECUTE ON FUNCTION cluster_timeline() TO probectl_app;
