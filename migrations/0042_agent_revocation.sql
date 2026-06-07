-- 0042_agent_revocation.sql
-- Sprint 12 (WIRE-003 residual): persisted agent revocation. Sprint 11 records
-- every issued SVID serial in agent_identities; revoking an agent stamps its
-- rows so (a) the live handshake deny-list can be fed/reloaded across restarts
-- and (b) enrollment/rotation refuse the revoked agent id.

ALTER TABLE agent_identities ADD COLUMN IF NOT EXISTS revoked_at timestamptz;
ALTER TABLE agent_identities ADD COLUMN IF NOT EXISTS revoked_by text NOT NULL DEFAULT '';

-- The boot/refresh reload reads only revoked rows; keep that scan cheap.
CREATE INDEX IF NOT EXISTS agent_identities_revoked_idx
  ON agent_identities (revoked_at) WHERE revoked_at IS NOT NULL;
