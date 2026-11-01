-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-2: authoritative identity is scoped by tenant and server-owned routing
-- context. Evidence may disagree; no unique alias constraint picks a winner.
CREATE TABLE IF NOT EXISTS entity_contexts (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    site_id uuid NOT NULL,
    vrf_id uuid NOT NULL,
    site_label text NOT NULL CHECK (octet_length(site_label) BETWEEN 1 AND 128),
    vrf_label text NOT NULL CHECK (octet_length(vrf_label) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, site_id, vrf_id),
    UNIQUE (tenant_id, site_label, vrf_label),
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (site_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (vrf_id <> '00000000-0000-0000-0000-000000000000'::uuid)
);
-- The current path engine runs on the control plane, not on an agent. A test
-- must therefore receive its routing context from an operator-owned binding,
-- never from an API request or a hop address. The composite FK prevents a
-- same-ID test in another tenant from selecting this context.
CREATE TABLE IF NOT EXISTS entity_path_test_contexts (
    tenant_id uuid NOT NULL,
    test_id uuid NOT NULL,
    context_id uuid NOT NULL,
    -- pathstore stores rounds by tenant+destination, not test UUID. Only one
    -- test may bind a normalized destination to a routing context at a time.
    path_target text NOT NULL CHECK (octet_length(path_target) BETWEEN 1 AND 1024),
    assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, test_id),
    CONSTRAINT entity_path_target_one_context UNIQUE (tenant_id, path_target),
    FOREIGN KEY (tenant_id, test_id)
        REFERENCES tests(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id)
        REFERENCES entity_contexts(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS entity_path_test_contexts_context_idx
    ON entity_path_test_contexts(tenant_id, context_id, test_id);
-- The path store keeps rounds by tenant+destination. A test target edit must
-- release its old context binding in the same database transaction, including
-- updates outside the API; the operator assigns the new destination again.
CREATE OR REPLACE FUNCTION public.entity_clear_path_binding_on_retarget()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.target IS DISTINCT FROM OLD.target THEN
        EXECUTE format('DELETE FROM %I.entity_path_test_contexts WHERE tenant_id=$1 AND test_id=$2',
                       TG_TABLE_SCHEMA)
            USING OLD.tenant_id, OLD.id;
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS entity_path_retarget ON tests;
CREATE TRIGGER entity_path_retarget AFTER UPDATE OF target ON tests
    FOR EACH ROW EXECUTE FUNCTION public.entity_clear_path_binding_on_retarget();
ALTER TABLE tests ENABLE ALWAYS TRIGGER entity_path_retarget;
-- A sender-bound evidence SVID names one agent. That identity may report
-- several configured sources, but only inside one routing context. The agent
-- must use a separate registered identity to author another VRF's evidence.
CREATE TABLE IF NOT EXISTS entity_agent_contexts (
    tenant_id uuid NOT NULL,
    agent_id text NOT NULL CHECK (octet_length(agent_id) BETWEEN 1 AND 128),
    context_id uuid NOT NULL,
    assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz,
    PRIMARY KEY (tenant_id, agent_id),
    UNIQUE (tenant_id, agent_id, context_id),
    FOREIGN KEY (tenant_id, context_id)
        REFERENCES entity_contexts(tenant_id, id) ON DELETE CASCADE,
    CHECK (expires_at IS NULL OR expires_at >= assigned_at)
);
ALTER TABLE entity_agent_contexts ALTER COLUMN assigned_at SET DEFAULT clock_timestamp();
CREATE INDEX IF NOT EXISTS entity_agent_contexts_tenant_context_idx
    ON entity_agent_contexts(tenant_id, context_id, agent_id);
-- An operator-owned source assignment is the only way an authenticated
-- collector/target can select a routing context. A packet address is never a
-- context key. An absent or expired assignment stays unresolved.
CREATE TABLE IF NOT EXISTS entity_source_contexts (
    tenant_id uuid NOT NULL,
    agent_id text NOT NULL CHECK (octet_length(agent_id) BETWEEN 1 AND 128),
    source_kind text NOT NULL CHECK (source_kind IN
        ('device_target', 'flow_exporter', 'path_agent', 'bmp_peer', 'agent_site')),
    source_ref text NOT NULL CHECK (octet_length(source_ref) BETWEEN 1 AND 1024),
    context_id uuid NOT NULL,
    -- Optional operator-owned canonical anchor. Untrusted evidence requests
    -- never provide entity_id; device_target assignments must set this via
    -- the administrative API before they can author canonical claims.
    anchor_entity_id uuid,
    assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz,
    PRIMARY KEY (tenant_id, agent_id, source_kind, source_ref),
    FOREIGN KEY (tenant_id, context_id)
        REFERENCES entity_contexts(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, agent_id, context_id)
        REFERENCES entity_agent_contexts(tenant_id, agent_id, context_id)
        ON UPDATE CASCADE ON DELETE CASCADE,
    -- Equal endpoints are an empty validity interval. Revocation can close
    -- a future-dated assignment at its start without leaving a live instant.
    CHECK (expires_at IS NULL OR expires_at >= assigned_at)
);
ALTER TABLE entity_source_contexts ALTER COLUMN assigned_at SET DEFAULT clock_timestamp();
CREATE INDEX IF NOT EXISTS entity_source_contexts_tenant_context_idx
    ON entity_source_contexts(tenant_id, context_id, source_kind, agent_id);
CREATE TABLE IF NOT EXISTS entities (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN
        ('device', 'interface', 'address', 'prefix', 'service', 'site', 'customer')),
    label text NOT NULL CHECK (octet_length(label) BETWEEN 1 AND 1024),
    parent_entity_id uuid,
    source_agent_id text,
    configured_ref text,
    interface_index bigint,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, context_id, id),
    FOREIGN KEY (tenant_id, context_id)
        REFERENCES entity_contexts(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id, parent_entity_id)
        REFERENCES entities(tenant_id, context_id, id) ON DELETE CASCADE,
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (parent_entity_id IS NULL OR kind = 'interface'),
    CHECK (interface_index IS NULL OR
           (kind = 'interface' AND parent_entity_id IS NOT NULL
            AND source_agent_id IS NOT NULL AND configured_ref IS NOT NULL
            AND interface_index BETWEEN 1 AND 4294967295)),
    CHECK (source_agent_id IS NULL OR octet_length(source_agent_id) BETWEEN 1 AND 128),
    CHECK (configured_ref IS NULL OR octet_length(configured_ref) BETWEEN 1 AND 1024)
);
CREATE INDEX IF NOT EXISTS entities_tenant_kind_idx
    ON entities(tenant_id, context_id, kind, id);
CREATE UNIQUE INDEX IF NOT EXISTS entities_source_interface_uidx
    ON entities(tenant_id, context_id, source_agent_id, configured_ref, interface_index)
    WHERE interface_index IS NOT NULL;
-- Add after entities exists: the source table is created earlier so its
-- agent/context constraints can be declared with the source definition.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='entity_source_contexts'::regclass
                     AND conname='entity_source_anchor_fk') THEN
        ALTER TABLE entity_source_contexts
            ADD CONSTRAINT entity_source_anchor_fk
            FOREIGN KEY (tenant_id, context_id, anchor_entity_id)
            REFERENCES entities(tenant_id, context_id, id)
            ON DELETE SET NULL (anchor_entity_id);
    END IF;
END $$;
CREATE TABLE IF NOT EXISTS entity_evidence (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL,
    observation_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    -- Only an unanchored flow/BMP match uses inferred support. A current read
    -- rechecks this exact independent SNMP row and address uniqueness.
    support_evidence_id uuid,
    alias_kind text NOT NULL CHECK (alias_kind IN
        ('address', 'prefix', 'snmp_device_id', 'snmp_interface_id', 'physical_neighbor_id',
         'flow_exporter_id', 'bmp_peer_id', 'path_hop_id', 'agent_site_id',
         'site_key', 'customer_key', 'service_key')),
    alias_value text NOT NULL CHECK (octet_length(alias_value) BETWEEN 1 AND 1024),
    source text NOT NULL CHECK (octet_length(source) BETWEEN 1 AND 128),
    source_ref text NOT NULL CHECK (octet_length(source_ref) BETWEEN 1 AND 1024),
    agent_id text NOT NULL CHECK (octet_length(agent_id) BETWEEN 1 AND 128),
    source_kind text NOT NULL CHECK (source_kind IN
        ('device_target', 'flow_exporter', 'path_agent', 'bmp_peer', 'agent_site')),
    configured_ref text NOT NULL CHECK (octet_length(configured_ref) BETWEEN 1 AND 1024),
    sender_serial text NOT NULL CHECK (sender_serial ~ '^[0-9a-f]{1,128}$'),
    origin_serial text,
    interface_name text,
    interface_description text,
    neighbor_protocol text,
    neighbor_local_if_index bigint,
    neighbor_local_port_id text,
    neighbor_remote_port_id text,
    neighbor_chassis_id text,
    neighbor_device_name text,
    neighbor_management_address text,
    observed_at timestamptz NOT NULL,
    expires_at timestamptz,
    PRIMARY KEY (tenant_id, context_id, id),
    UNIQUE (tenant_id, agent_id, source_kind, configured_ref, observation_id),
    FOREIGN KEY (tenant_id, context_id, entity_id)
        REFERENCES entities(tenant_id, context_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id, support_evidence_id)
        REFERENCES entity_evidence(tenant_id, context_id, id) ON DELETE CASCADE,
    CHECK (support_evidence_id IS NULL OR source_kind IN ('flow_exporter','bmp_peer')),
    CHECK (expires_at IS NULL OR expires_at > observed_at),
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (observation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK ((source_kind = 'bmp_peer') = (origin_serial IS NOT NULL)),
    CHECK (alias_kind = 'snmp_interface_id' OR
           (interface_name IS NULL AND interface_description IS NULL)),
    CHECK (interface_name IS NULL OR octet_length(interface_name) BETWEEN 1 AND 1024),
    CHECK (interface_description IS NULL OR octet_length(interface_description) BETWEEN 1 AND 1024),
    CHECK ((alias_kind = 'physical_neighbor_id') = (neighbor_protocol IS NOT NULL)),
    CHECK (neighbor_protocol IS NULL OR (
        neighbor_protocol IN ('lldp','cdp') AND
        neighbor_local_if_index IS NOT NULL AND
        neighbor_local_if_index BETWEEN 1 AND 4294967295 AND
        neighbor_local_port_id IS NOT NULL AND
        octet_length(neighbor_local_port_id) BETWEEN 1 AND 256 AND
        neighbor_remote_port_id IS NOT NULL AND
        octet_length(neighbor_remote_port_id) BETWEEN 1 AND 256 AND
        (neighbor_management_address IS NOT NULL OR neighbor_device_name IS NOT NULL))),
    CHECK (neighbor_protocol IS NOT NULL OR (
        neighbor_local_if_index IS NULL AND neighbor_local_port_id IS NULL AND
        neighbor_remote_port_id IS NULL AND neighbor_chassis_id IS NULL AND
        neighbor_device_name IS NULL AND neighbor_management_address IS NULL)),
    CHECK (neighbor_chassis_id IS NULL OR octet_length(neighbor_chassis_id) BETWEEN 1 AND 256),
    CHECK (neighbor_device_name IS NULL OR octet_length(neighbor_device_name) BETWEEN 1 AND 256),
    CHECK (neighbor_management_address IS NULL OR octet_length(neighbor_management_address) BETWEEN 1 AND 255),
    CHECK (origin_serial IS NULL OR origin_serial ~ '^[0-9a-f]{1,128}$')
);
CREATE INDEX IF NOT EXISTS entity_evidence_tenant_alias_idx
    ON entity_evidence(tenant_id, context_id, alias_kind, alias_value,
                       entity_id, observed_at DESC, id);
CREATE INDEX IF NOT EXISTS entity_evidence_tenant_entity_idx
    ON entity_evidence(tenant_id, context_id, entity_id, observed_at DESC, id);
CREATE INDEX IF NOT EXISTS entity_evidence_tenant_source_idx
    ON entity_evidence(tenant_id, context_id, agent_id, source_kind, configured_ref);
CREATE INDEX IF NOT EXISTS entity_evidence_tenant_support_idx
    ON entity_evidence(tenant_id, context_id, support_evidence_id)
    WHERE support_evidence_id IS NOT NULL;
CREATE TABLE IF NOT EXISTS entity_links (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL,
    from_entity_id uuid NOT NULL,
    to_entity_id uuid NOT NULL,
    evidence_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN
        ('physical', 'inferred', 'routing', 'contains', 'serves', 'assigned_to')),
    observed_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, context_id, id),
    FOREIGN KEY (tenant_id, context_id, from_entity_id)
        REFERENCES entities(tenant_id, context_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id, to_entity_id)
        REFERENCES entities(tenant_id, context_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id, evidence_id)
        REFERENCES entity_evidence(tenant_id, context_id, id) ON DELETE CASCADE,
    CHECK (from_entity_id <> to_entity_id),
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid)
);
CREATE INDEX IF NOT EXISTS entity_links_tenant_from_idx
    ON entity_links(tenant_id, context_id, from_entity_id, id);
CREATE INDEX IF NOT EXISTS entity_links_tenant_to_idx
    ON entity_links(tenant_id, context_id, to_entity_id, id);
-- One signed LLDP/CDP observation names one remote physical endpoint. A
-- repeated writer call cannot attach the same evidence to a second device.
CREATE UNIQUE INDEX IF NOT EXISTS entity_links_one_physical_per_evidence_uidx
    ON entity_links(tenant_id, context_id, evidence_id)
    WHERE kind = 'physical';

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'entity_contexts', 'entity_path_test_contexts', 'entity_agent_contexts',
        'entity_source_contexts', 'entities',
        'entity_evidence', 'entity_links'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = NULLIF(current_setting(''probectl.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting(''probectl.tenant_id'', true), '''')::uuid)',
            table_name
        );
        EXECUTE format('DROP TRIGGER IF EXISTS tenant_write_fence ON %I', table_name);
        EXECUTE format(
            'CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()',
            table_name
        );
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER tenant_write_fence', table_name);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO probectl_app', table_name);
    END LOOP;
END $$;
