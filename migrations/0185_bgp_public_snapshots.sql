-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- One complete public source generation, including an empty RIB. Peer/family
-- rows remain private until the whole declared manifest completes. The header
-- is not itself a grant: current collector authority is checked on every read.
CREATE TABLE IF NOT EXISTS bgp_public_snapshots (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL CHECK (id<>'00000000-0000-0000-0000-000000000000'::uuid),
    collector_agent_id text NOT NULL CHECK (collector_agent_id<>''),
    source_kind text NOT NULL DEFAULT 'public_bgp' CHECK (source_kind='public_bgp'),
    source_ref text NOT NULL CHECK (source_ref<>''),
    sender_serial text NOT NULL CHECK (sender_serial<>''),
    manifest_digest bytea NOT NULL CHECK (octet_length(manifest_digest)=32),
    expected_views bigint NOT NULL CHECK (expected_views>=0),
    state text NOT NULL CHECK (state IN ('staging','current','invalid')),
    observed_at timestamptz NOT NULL,
    observed_unix_nanos bigint NOT NULL CHECK (observed_unix_nanos>=0),
    last_message_unix_nanos bigint NOT NULL,
    valid_until timestamptz NOT NULL,
    completed_at timestamptz,
    next_sequence bigint NOT NULL DEFAULT 1 CHECK (next_sequence>0),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence>=0),
    last_digest bytea,
    charged_bytes bigint NOT NULL CHECK (charged_bytes>=256),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,context_id,id),
    UNIQUE (tenant_id,context_id,id,collector_agent_id,source_ref,sender_serial),
    CONSTRAINT fx5_public_snapshot_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fx5_public_snapshot_context_fk FOREIGN KEY (tenant_id,context_id)
        REFERENCES entity_contexts(tenant_id,id) ON DELETE CASCADE,
    CONSTRAINT fx5_public_snapshot_source_fk
        FOREIGN KEY (tenant_id,context_id,collector_agent_id,source_kind,source_ref)
        REFERENCES entity_source_contexts(tenant_id,context_id,agent_id,source_kind,source_ref)
        ON DELETE CASCADE,
    CHECK (valid_until>observed_at),
    CHECK (observed_unix_nanos/1000=(extract(epoch FROM observed_at)*1000000)::bigint),
    CHECK (last_message_unix_nanos>=observed_unix_nanos),
    CHECK (last_sequence=next_sequence-1),
    CHECK ((last_sequence=0 AND last_digest IS NULL)
        OR (last_sequence>0 AND last_digest IS NOT NULL AND octet_length(last_digest)=32)),
    CHECK (state<>'current' OR completed_at IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS bgp_public_snapshots_current_idx
    ON bgp_public_snapshots(tenant_id,context_id,collector_agent_id,source_ref)
    WHERE state='current';
CREATE INDEX IF NOT EXISTS bgp_public_snapshots_source_idx
    ON bgp_public_snapshots(tenant_id,context_id,collector_agent_id,source_ref,observed_unix_nanos);

ALTER TABLE bgp_public_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE bgp_public_snapshots FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON bgp_public_snapshots;
CREATE POLICY tenant_isolation ON bgp_public_snapshots
    USING (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);
DROP TRIGGER IF EXISTS tenant_write_fence ON bgp_public_snapshots;
CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON bgp_public_snapshots
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE bgp_public_snapshots ENABLE ALWAYS TRIGGER tenant_write_fence;
GRANT SELECT,INSERT,UPDATE,DELETE ON bgp_public_snapshots TO probectl_app;

ALTER TABLE bgp_routing_views ADD COLUMN IF NOT EXISTS public_snapshot_id uuid;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='bgp_routing_views'::regclass
                   AND conname='fx5_public_view_snapshot_fk') THEN
        ALTER TABLE bgp_routing_views ADD CONSTRAINT fx5_public_view_snapshot_fk
            FOREIGN KEY (tenant_id,context_id,public_snapshot_id,collector_agent_id,source_ref,sender_serial)
            REFERENCES bgp_public_snapshots(tenant_id,context_id,id,collector_agent_id,source_ref,sender_serial)
            ON DELETE CASCADE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='bgp_routing_views'::regclass
                   AND conname='fx5_public_view_snapshot_shape') THEN
        -- Legacy unbound private staging cannot become current. No existing
        -- retained data is rewritten or silently promoted during an upgrade.
        ALTER TABLE bgp_routing_views ADD CONSTRAINT fx5_public_view_snapshot_shape CHECK (
            (public_snapshot_id IS NULL OR source_kind='public_bgp')
            AND (source_kind<>'public_bgp' OR state<>'current' OR public_snapshot_id IS NOT NULL)) NOT VALID;
    END IF;
END $$;
