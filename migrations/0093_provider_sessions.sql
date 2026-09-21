-- SPDX-License-Identifier: BUSL-1.1
--
-- DPR-033: provider operator sessions are persisted so every control replica
-- validates the same session and disabling an operator ends it everywhere.
-- Provider-domain table: no tenant_id by design (operators are the privilege
-- domain above tenants). Only the keyed hash of the token is stored.
CREATE TABLE IF NOT EXISTS provider_sessions (
    token_hash       text PRIMARY KEY,
    operator_id      uuid NOT NULL REFERENCES provider_operators(id) ON DELETE CASCADE,
    issued_at        timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    last_activity_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS provider_sessions_operator_idx ON provider_sessions (operator_id);
