-- 0054: Cluster-wide singleton lease epochs for side-effecting background work.
--
-- The actual mutual exclusion is a session-scoped PostgreSQL advisory lock.
-- This GLOBAL (not tenant-owned) row is the fencing ledger: every successful
-- acquisition increments epoch, and renew/release updates must match both that
-- epoch and holder id. A stale worker therefore cannot present an old token as
-- current after failover.

CREATE TABLE IF NOT EXISTS cluster_singleton_leases (
    lease_name text PRIMARY KEY,
    epoch bigint NOT NULL DEFAULT 0 CHECK (epoch >= 0),
    holder_id text NOT NULL DEFAULT '',
    acquired_at timestamptz,
    renewed_at timestamptz,
    released_at timestamptz
);

-- The control-plane app role coordinates the global background lease. The
-- advisory lock remains the authority; table access alone cannot acquire it.
GRANT SELECT, INSERT, UPDATE ON cluster_singleton_leases TO probectl_app;
