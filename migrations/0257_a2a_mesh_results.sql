-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

CREATE TABLE IF NOT EXISTS public.a2a_mesh_results (
    tenant_id uuid NOT NULL CONSTRAINT a2a_mesh_result_tenant_fk
        REFERENCES public.tenants(id) ON DELETE CASCADE,
    session_id text NOT NULL CHECK (session_id ~ '^[0-9a-f]{32}$'),
    role text NOT NULL CHECK (role IN ('initiator', 'responder')),
    agent_id uuid NOT NULL,
    peer_agent_id uuid NOT NULL CHECK (peer_agent_id <> agent_id),
    result_id uuid NOT NULL,
    payload_sha256 bytea NOT NULL CHECK (octet_length(payload_sha256) = 32),
    started_unix_nano bigint NOT NULL CHECK (started_unix_nano > 0),
    duration_nano bigint NOT NULL CHECK (duration_nano > 0),
    expires_at timestamptz NOT NULL,
    metrics jsonb NOT NULL CHECK (jsonb_typeof(metrics) = 'object'),
    PRIMARY KEY (tenant_id, session_id, role),
    UNIQUE (tenant_id, result_id)
);

CREATE INDEX IF NOT EXISTS a2a_mesh_result_expiry
    ON public.a2a_mesh_results (tenant_id, expires_at);

ALTER TABLE public.a2a_mesh_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.a2a_mesh_results FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON public.a2a_mesh_results;
CREATE POLICY tenant_isolation ON public.a2a_mesh_results
    USING (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('probectl.tenant_id', true), '')::uuid);
DROP TRIGGER IF EXISTS tenant_write_fence ON public.a2a_mesh_results;
CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON public.a2a_mesh_results
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE public.a2a_mesh_results ENABLE ALWAYS TRIGGER tenant_write_fence;
GRANT SELECT, INSERT, DELETE ON public.a2a_mesh_results TO probectl_app;
