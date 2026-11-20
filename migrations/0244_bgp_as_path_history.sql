-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- The existing visibility monitor owns both public and private path history.
-- The collection source and the original receipt live on every observation.
CREATE TABLE IF NOT EXISTS bgp_as_path_history (
    tenant_id uuid NOT NULL,
    monitor_id uuid NOT NULL,
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    source_kind text NOT NULL CHECK (source_kind IN ('router_bmp','public_mrt')),
    vantage_key text NOT NULL CHECK (octet_length(vantage_key) BETWEEN 1 AND 256),
    source_epoch text NOT NULL CHECK (octet_length(source_epoch) BETWEEN 1 AND 128),
    event_digest bytea NOT NULL CHECK (octet_length(event_digest)=32),
    observed_at timestamptz NOT NULL,
    source_sequence bigint NOT NULL CHECK (source_sequence>=0),
    source_operation integer NOT NULL CHECK (source_operation>=0),
    has_path_id boolean NOT NULL,
    path_id bigint NOT NULL CHECK (path_id BETWEEN 0 AND 4294967295),
    context_id uuid,
    router_id uuid,
    collector_agent_id text CHECK (octet_length(collector_agent_id)>0),
    source_ref text CHECK (octet_length(source_ref) BETWEEN 1 AND 1024),
    change_event_id uuid,
    event_kind text NOT NULL CHECK (event_kind IN ('baseline','announcement','withdrawal','path_change','coverage_gap')),
    original jsonb NOT NULL CHECK (jsonb_typeof(original)='object'),
    previous_path jsonb CHECK (jsonb_typeof(previous_path)='object'),
    current_path jsonb CHECK (jsonb_typeof(current_path)='object'),
    PRIMARY KEY (tenant_id,monitor_id,observed_at,id),
    UNIQUE (tenant_id,monitor_id,source_kind,vantage_key,source_epoch,source_sequence,source_operation,event_digest),
    FOREIGN KEY (tenant_id,monitor_id) REFERENCES bgp_visibility_monitors(tenant_id,id) ON DELETE CASCADE,
    CHECK (has_path_id OR path_id=0),
    CHECK ((source_kind='router_bmp' AND context_id IS NOT NULL AND router_id IS NOT NULL
            AND collector_agent_id IS NOT NULL AND source_ref IS NOT NULL)
        OR (source_kind='public_mrt' AND context_id IS NULL AND router_id IS NULL
            AND collector_agent_id IS NULL AND source_ref IS NULL AND change_event_id IS NULL)),
    CHECK ((event_kind IN ('baseline','coverage_gap') AND previous_path IS NULL)
        OR (event_kind='announcement' AND previous_path IS NULL AND current_path IS NOT NULL)
        OR (event_kind='withdrawal' AND previous_path IS NOT NULL AND current_path IS NULL)
        OR (event_kind='path_change' AND previous_path IS NOT NULL AND current_path IS NOT NULL)),
    CHECK (event_kind<>'coverage_gap' OR current_path IS NULL)
);

CREATE INDEX IF NOT EXISTS bgp_as_path_history_vantage_clock_idx
    ON bgp_as_path_history(tenant_id,monitor_id,source_kind,vantage_key,observed_at DESC,source_sequence DESC,source_operation DESC,id DESC);

ALTER TABLE bgp_as_path_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE bgp_as_path_history FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON bgp_as_path_history;
CREATE POLICY tenant_isolation ON bgp_as_path_history
    USING (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);

GRANT SELECT, INSERT, DELETE ON bgp_as_path_history TO probectl_app;
DROP TRIGGER IF EXISTS tenant_write_fence ON public.bgp_as_path_history;
CREATE TRIGGER tenant_write_fence
    BEFORE INSERT ON public.bgp_as_path_history
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE public.bgp_as_path_history ENABLE ALWAYS TRIGGER tenant_write_fence;
