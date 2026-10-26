-- 0131: a persisted online status is not evidence of a current heartbeat.
-- Keep the provider's aggregate-only boundary and the existing five-minute
-- stale threshold. Missing heartbeat timestamps cannot count as online.
-- Idempotent replacement; no tenant rows, grants, or view columns change.
CREATE OR REPLACE VIEW provider_agent_fleet_counts AS
  SELECT a.tenant_id,
         count(*) AS agents_total,
         count(*) FILTER (WHERE a.status = 'online'
                            AND a.last_seen_at >= now() - interval '5 minutes') AS agents_online,
         count(*) FILTER (WHERE a.status = 'online'
                            AND a.last_seen_at < now() - interval '5 minutes') AS agents_stale
    FROM agents a
   GROUP BY a.tenant_id;
