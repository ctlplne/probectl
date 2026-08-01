-- 0088: replace the provider role's unconstrained cross-tenant SELECT on
-- agents with aggregate-only views (Foundation-Loop S-1612260f).
--
-- 0024 granted probectl_provider `SELECT ON agents` plus a
-- `provider_fleet_read ... USING (true)` policy. Migration 0045 performed
-- EXACTLY this tightening for audit_events — naming a `USING(true)` provider
-- SELECT an "unconstrained cross-tenant read capability" — and then did not
-- come back for agents. Any provider query later written against that table
-- inherited a cross-tenant row read that no test would catch, contradicting
-- "provider operators get no implicit read access to tenant data"
-- (CLAUDE.md §7 guardrail 1).
--
-- The fleet console needs COUNTS and VERSION HISTOGRAMS, never agent rows. So
-- the capability becomes exactly that: two security-invoker-free views owned
-- by the migration role that expose aggregates only, and the underlying table
-- grant is revoked. A future provider query cannot select agent identity,
-- hostname, labels or last-seen detail, because the capability to read rows no
-- longer exists.
--
-- Idempotent + expand-only (CLAUDE.md §6): views are created/replaced and a
-- grant is revoked; no table, column, or row is dropped or rewritten.

-- Per-tenant agent counts (the fleet table's totals/online/stale columns).
CREATE OR REPLACE VIEW provider_agent_fleet_counts AS
  SELECT a.tenant_id,
         count(*)                                                         AS agents_total,
         count(*) FILTER (WHERE a.status = 'online')                      AS agents_online,
         count(*) FILTER (WHERE a.status = 'online'
                            AND a.last_seen_at < now() - interval '5 minutes') AS agents_stale
    FROM agents a
   GROUP BY a.tenant_id;

-- Per-tenant agent-version histogram (the rollout view).
CREATE OR REPLACE VIEW provider_agent_fleet_versions AS
  SELECT a.tenant_id, a.agent_version, count(*) AS agents
    FROM agents a
   WHERE a.agent_version <> ''
   GROUP BY a.tenant_id, a.agent_version;

-- The views run with the DEFINER's rights (PostgreSQL's default for views),
-- so they read agents without the provider role holding that capability. That
-- is the point: the aggregate is grantable, the rows are not.
GRANT SELECT ON provider_agent_fleet_counts   TO probectl_provider;
GRANT SELECT ON provider_agent_fleet_versions TO probectl_provider;

-- Remove the unconstrained row-read capability itself.
DROP POLICY IF EXISTS provider_fleet_read ON agents;
REVOKE SELECT ON agents FROM probectl_provider;
