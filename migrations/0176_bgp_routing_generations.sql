-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- A complete source/view generation is private while staging. Publication and
-- all reads must establish current source/credential/context authority; a row's
-- state alone is not that authority. No route/path population ceiling is stored.
CREATE TABLE IF NOT EXISTS bgp_routing_views (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL CHECK (id<>'00000000-0000-0000-0000-000000000000'::uuid),
    generation uuid NOT NULL CHECK (generation<>'00000000-0000-0000-0000-000000000000'::uuid),
    source_kind text NOT NULL CHECK (source_kind IN ('router_bmp','public_bgp')),
    router_id uuid,
    router_kind text NOT NULL DEFAULT 'device' CHECK (router_kind='device'),
    collector_agent_id text NOT NULL CHECK (collector_agent_id<>''),
    source_ref text NOT NULL CHECK (source_ref<>''),
    binding_kind text,
    sender_serial text NOT NULL CHECK (sender_serial<>''),
    origin_serial text,
    view_kind text NOT NULL CHECK (view_kind IN (
        'adj_rib_in_pre_policy','adj_rib_in_post_policy',
        'adj_rib_out_pre_policy','adj_rib_out_post_policy','loc_rib','public_bgp')),
    peer_key bytea NOT NULL CHECK (octet_length(peer_key)=32),
    peer_identity jsonb NOT NULL CHECK (jsonb_typeof(peer_identity)='object'),
    afi integer NOT NULL CHECK (afi IN (1,2)),
    safi integer NOT NULL CHECK (safi=1),
    filtered boolean NOT NULL,
    state text NOT NULL CHECK (state IN ('staging','current','invalid')),
    next_sequence bigint NOT NULL DEFAULT 1 CHECK (next_sequence>0),
    last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence>=0),
    last_digest bytea,
    row_count bigint NOT NULL DEFAULT 0 CHECK (row_count>=0),
    charged_bytes bigint NOT NULL DEFAULT 0 CHECK (charged_bytes>=0),
    observed_at timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    completed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,context_id,id,generation),
    UNIQUE (tenant_id,context_id,id,generation,afi,safi),
    CONSTRAINT fx5_route_view_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fx5_route_view_context_fk FOREIGN KEY (tenant_id,context_id)
        REFERENCES entity_contexts(tenant_id,id) ON DELETE CASCADE,
    CONSTRAINT fx5_route_view_router_fk FOREIGN KEY (tenant_id,context_id,router_id,router_kind)
        REFERENCES entities(tenant_id,context_id,id,kind) ON DELETE CASCADE,
    CONSTRAINT fx5_route_view_agent_context_fk FOREIGN KEY (tenant_id,collector_agent_id,context_id)
        REFERENCES entity_agent_contexts(tenant_id,agent_id,context_id) ON DELETE CASCADE,
    CONSTRAINT fx5_route_view_source_fk FOREIGN KEY (tenant_id,collector_agent_id,binding_kind,source_ref)
        REFERENCES entity_source_contexts(tenant_id,agent_id,source_kind,source_ref) ON DELETE CASCADE,
    CHECK (valid_until>observed_at),
    CHECK ((last_sequence=0 AND last_digest IS NULL)
        OR (last_sequence>0 AND last_digest IS NOT NULL AND octet_length(last_digest)=32)),
    CHECK (last_sequence=next_sequence-1),
    CHECK (state<>'current' OR completed_at IS NOT NULL),
    CHECK ((source_kind='router_bmp' AND router_id IS NOT NULL
             AND router_id<>'00000000-0000-0000-0000-000000000000'::uuid
             AND binding_kind IS NOT NULL AND binding_kind='bmp_peer' AND view_kind<>'public_bgp'
             AND origin_serial IS NOT NULL AND origin_serial<>'')
        OR (source_kind='public_bgp' AND router_id IS NULL
             AND binding_kind IS NULL AND view_kind='public_bgp'
             AND origin_serial IS NULL))
);

-- Only one current incarnation of a logical source/view/family. Failed or
-- incomplete replacements cannot appear current by choosing another view UUID.
CREATE UNIQUE INDEX IF NOT EXISTS bgp_routing_views_current_idx
    ON bgp_routing_views (
        tenant_id,context_id,source_kind,
        (COALESCE(router_id,'00000000-0000-0000-0000-000000000000'::uuid)),
        collector_agent_id,source_ref,view_kind,peer_key,afi,safi)
    WHERE state='current';
CREATE INDEX IF NOT EXISTS bgp_routing_views_router_idx
    ON bgp_routing_views (tenant_id,context_id,router_id,state,afi,safi);

CREATE TABLE IF NOT EXISTS bgp_routing_entries (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    view_id uuid NOT NULL,
    generation uuid NOT NULL,
    afi integer NOT NULL CHECK (afi IN (1,2)),
    safi integer NOT NULL CHECK (safi=1),
    prefix cidr NOT NULL,
    has_path_id boolean NOT NULL,
    path_id bigint NOT NULL CHECK (path_id BETWEEN 0 AND 4294967295),
    segments jsonb NOT NULL CHECK (jsonb_typeof(segments)='array'),
    attributes jsonb NOT NULL CHECK (jsonb_typeof(attributes)='object'),
    next_hops inet[] NOT NULL,
    sequence bigint NOT NULL CHECK (sequence>0),
    observed_at timestamptz NOT NULL,
    charged_bytes bigint NOT NULL CHECK (charged_bytes>0),
    PRIMARY KEY (tenant_id,context_id,view_id,generation,prefix,has_path_id,path_id),
    CONSTRAINT fx5_route_entry_view_fk FOREIGN KEY (tenant_id,context_id,view_id,generation,afi,safi)
        REFERENCES bgp_routing_views(tenant_id,context_id,id,generation,afi,safi) ON DELETE CASCADE,
    CHECK (has_path_id OR path_id=0),
    CHECK ((afi=1 AND family(prefix)=4) OR (afi=2 AND family(prefix)=6))
);

-- The leading tenant/context/view keys also support bounded exact-prefix
-- probes for every legal mask length without an extension or global dictionary.
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['bgp_routing_views','bgp_routing_entries'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY',table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY',table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I',table_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I
            USING (tenant_id=NULLIF(current_setting(''probectl.tenant_id'',true),'''')::uuid)
            WITH CHECK (tenant_id=NULLIF(current_setting(''probectl.tenant_id'',true),'''')::uuid)',table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS tenant_write_fence ON %I',table_name);
        EXECUTE format('CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON %I
            FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()',table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER tenant_write_fence',table_name);
        EXECUTE format('GRANT SELECT,INSERT,UPDATE,DELETE ON %I TO probectl_app',table_name);
    END LOOP;
END $$;
