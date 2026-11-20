-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

ALTER TABLE entity_source_contexts
    DROP CONSTRAINT IF EXISTS entity_source_contexts_source_kind_check;
ALTER TABLE entity_source_contexts
    ADD CONSTRAINT entity_source_contexts_source_kind_check CHECK (source_kind IN
        ('device_target','flow_exporter','path_agent','bmp_peer','agent_site','public_bgp','dns_resolver')) NOT VALID;
DO $dns_source_shape$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='entity_source_contexts'::regclass
                   AND conname='resolver_dns_source_shape') THEN
        ALTER TABLE entity_source_contexts ADD CONSTRAINT resolver_dns_source_shape
            CHECK (source_kind<>'dns_resolver' OR
                   (anchor_entity_id IS NOT NULL AND routing_epoch IS NULL
                    AND routing_assigned_at IS NULL AND routing_bindings IS NULL)) NOT VALID;
    END IF;
END $dns_source_shape$;

ALTER TABLE entity_fault_receipts
    DROP CONSTRAINT IF EXISTS entity_fault_receipts_source_kind_check;
ALTER TABLE entity_fault_receipts
    ADD CONSTRAINT entity_fault_receipts_source_kind_check CHECK
        (source_kind IN ('device_target','flow_exporter','dns_resolver')) NOT VALID;

-- Evidence is the reduced response population from a closed local file.
-- Source generation and the tenant hold the assignment; DNS contents are absent.
CREATE TABLE IF NOT EXISTS resolver_dns_intervals (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    device_id uuid NOT NULL,
    agent_id text NOT NULL,
    source_kind text NOT NULL DEFAULT 'dns_resolver' CHECK (source_kind='dns_resolver'),
    source_ref text NOT NULL CHECK (source_ref ~ '^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$'),
    source_assigned_at timestamptz NOT NULL,
    agent_assigned_at timestamptz NOT NULL,
    minute_start timestamptz NOT NULL CHECK (minute_start=date_trunc('minute',minute_start)),
    client_responses integer NOT NULL CHECK (client_responses BETWEEN 0 AND 1048576),
    name_errors integer NOT NULL CHECK (name_errors BETWEEN 0 AND 1048576),
    server_failures integer NOT NULL CHECK (server_failures BETWEEN 0 AND 1048576),
    truncated integer NOT NULL CHECK (truncated BETWEEN 0 AND 1048576),
    capture_digest bytea NOT NULL CHECK (octet_length(capture_digest)=32),
    pressure_policy bytea NOT NULL CHECK (octet_length(pressure_policy) BETWEEN 1 AND 200),
    PRIMARY KEY (tenant_id,agent_id,source_kind,source_ref,source_assigned_at,agent_assigned_at,minute_start),
    FOREIGN KEY (tenant_id,context_id,device_id) REFERENCES entities(tenant_id,context_id,id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,agent_id,source_kind,source_ref)
        REFERENCES entity_source_contexts(tenant_id,agent_id,source_kind,source_ref) ON DELETE CASCADE,
    CHECK (name_errors+server_failures<=client_responses AND truncated<=client_responses)
);

CREATE INDEX IF NOT EXISTS resolver_dns_intervals_tenant_clock_idx
    ON resolver_dns_intervals(tenant_id,minute_start);
CREATE INDEX IF NOT EXISTS resolver_dns_intervals_tenant_device_idx
    ON resolver_dns_intervals(tenant_id,context_id,device_id,minute_start);

ALTER TABLE resolver_dns_intervals ENABLE ROW LEVEL SECURITY;
ALTER TABLE resolver_dns_intervals FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON resolver_dns_intervals;
CREATE POLICY tenant_isolation ON resolver_dns_intervals
    USING (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);
GRANT SELECT, INSERT, DELETE ON resolver_dns_intervals TO probectl_app;

DROP TRIGGER IF EXISTS tenant_write_fence ON public.resolver_dns_intervals;
CREATE TRIGGER tenant_write_fence
    BEFORE INSERT OR UPDATE ON public.resolver_dns_intervals
    FOR EACH ROW
    EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE public.resolver_dns_intervals ENABLE ALWAYS TRIGGER tenant_write_fence;
