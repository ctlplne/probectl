-- 0089: give stranded provisioning attempts a step ledger and an age the
-- reaper can act on (Foundation-Loop S-fadcec95).
--
-- tenant_provisioning is a staging row created before the external silo legs
-- run, and deleted only on the SUCCESS path. An attempt abandoned partway —
-- an operator closing the tab, a control-plane restart, a ClickHouse outage
-- that outlived the request — left a permanent staging row with (before the
-- provisioner became compensating) orphaned databases behind it, and there was
-- no sweeper and no way to find it.
--
-- last_step records the furthest leg the attempt completed, so the console can
-- show what actually happened and an operator can decide between retry and
-- abandon on evidence rather than a guess. last_attempt_at ages the row for
-- the reaper independently of created_at, so a retried attempt is not reaped
-- for being old.
--
-- Expand-only and idempotent: two nullable columns with defaults, no rewrite.
ALTER TABLE tenant_provisioning
    ADD COLUMN IF NOT EXISTS last_step       text NOT NULL DEFAULT 'registered',
    ADD COLUMN IF NOT EXISTS last_attempt_at timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN IF NOT EXISTS last_error      text NOT NULL DEFAULT '';

COMMENT ON COLUMN tenant_provisioning.last_step IS
    'furthest provisioning leg completed: registered | postgres | <ch plane> | complete';
COMMENT ON COLUMN tenant_provisioning.last_attempt_at IS
    'when provisioning was last attempted; the reaper ages stranded attempts from this, not created_at';

-- The reaper deletes stranded attempts; the console updates their ledger.
GRANT UPDATE ON tenant_provisioning TO probectl_provider;
