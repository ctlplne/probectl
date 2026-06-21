-- 0039_ai_answers.sql
-- U-093: optional persisted RCA artifacts. When PROBECTL_AI_PERSIST_ANSWERS is
-- on, every answer is privacy-minimized before storage (tenant-scoped tokens
-- replace raw prompts, IPs, emails, secrets, and configured custom patterns)
-- and stored with the model name and a hash of the AI configuration that
-- produced it. Retention is enforced opportunistically on write
-- (PROBECTL_AI_ANSWER_RETENTION). Tenant-owned: tenant_id + RLS from the first
-- migration (CLAUDE.md §6). Idempotent + backward-compatible.

CREATE TABLE IF NOT EXISTS ai_answers (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid        NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    answer_id   text        NOT NULL,
    question    text        NOT NULL DEFAULT '',
    root_cause  text        NOT NULL DEFAULT '',
    confidence  text        NOT NULL DEFAULT '',
    model       text        NOT NULL DEFAULT '',
    config_hash text        NOT NULL DEFAULT '',
    payload     jsonb       NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, answer_id)
);
CREATE INDEX IF NOT EXISTS ai_answers_tenant_idx ON ai_answers (tenant_id, created_at DESC);

ALTER TABLE ai_answers ENABLE ROW LEVEL SECURITY;
ALTER TABLE ai_answers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON ai_answers;
CREATE POLICY tenant_isolation ON ai_answers
  USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);

-- DELETE is needed for retention pruning (tenant-scoped via RLS).
GRANT SELECT, INSERT, DELETE ON ai_answers TO probectl_app;
