-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Operator-assigned sources. The source row is an immutable identity epoch.
-- A rebind closes that epoch and allocates a new ID even if its names repeat.
CREATE TABLE IF NOT EXISTS kubernetes_inventory_sources (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL,
    cluster_id uuid NOT NULL,
    namespace text NOT NULL CHECK (namespace ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    agent_id text NOT NULL CHECK (octet_length(agent_id) BETWEEN 1 AND 128),
    flow_clock_error_ms bigint CHECK (flow_clock_error_ms BETWEEN 0 AND 9223372036853),
    assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    closed_at timestamptz,
    PRIMARY KEY (tenant_id, context_id, id),
    UNIQUE (tenant_id, id),
    FOREIGN KEY (tenant_id, context_id)
        REFERENCES entity_contexts(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, agent_id, context_id)
        REFERENCES entity_agent_contexts(tenant_id, agent_id, context_id) ON DELETE CASCADE,
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (cluster_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (isfinite(assigned_at) AND (closed_at IS NULL OR (isfinite(closed_at) AND closed_at >= assigned_at)))
);
CREATE UNIQUE INDEX IF NOT EXISTS kubernetes_inventory_live_namespace_idx
    ON kubernetes_inventory_sources(tenant_id, context_id, cluster_id, namespace)
    WHERE closed_at IS NULL;

-- Staging is separate from the inventory tables read by Explorer and
-- topology. Expiring an incomplete upload deletes its parts by cascade.
CREATE TABLE IF NOT EXISTS kubernetes_inventory_staging (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    sender_serial text NOT NULL CHECK (sender_serial ~ '^[0-9a-f]{1,128}$'),
    manifest bytea NOT NULL CHECK (octet_length(manifest) > 0),
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    expected_parts bigint NOT NULL CHECK (expected_parts BETWEEN 0 AND 4294967295),
    expected_rows bigint NOT NULL CHECK (expected_rows >= 0),
    expected_bytes bigint NOT NULL CHECK (expected_bytes >= 0),
    next_part bigint NOT NULL DEFAULT 0,
    appended_rows bigint NOT NULL DEFAULT 0,
    appended_bytes bigint NOT NULL DEFAULT 0,
    opened_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, context_id, source_id, generation_id),
    FOREIGN KEY (tenant_id, context_id, source_id)
        REFERENCES kubernetes_inventory_sources(tenant_id, context_id, id) ON DELETE CASCADE,
    CHECK (generation_id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (next_part BETWEEN 0 AND expected_parts),
    CHECK (appended_rows BETWEEN 0 AND expected_rows),
    CHECK (appended_bytes BETWEEN 0 AND expected_bytes),
    CHECK (isfinite(opened_at) AND isfinite(expires_at) AND expires_at > opened_at),
    CHECK ((expected_parts = 0 AND expected_rows = 0 AND expected_bytes = 0) OR
           (expected_parts > 0 AND expected_rows >= expected_parts AND expected_bytes >= expected_parts))
);
CREATE INDEX IF NOT EXISTS kubernetes_inventory_staging_expiry_idx
    ON kubernetes_inventory_staging(tenant_id, expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS kubernetes_inventory_one_staged_upload_idx
    ON kubernetes_inventory_staging(tenant_id, context_id, source_id);

CREATE TABLE IF NOT EXISTS kubernetes_inventory_stage_parts (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    part_index bigint NOT NULL CHECK (part_index BETWEEN 0 AND 4294967294),
    original_wire bytea NOT NULL CHECK (octet_length(original_wire) > 0),
    PRIMARY KEY (tenant_id, context_id, source_id, generation_id, part_index),
    FOREIGN KEY (tenant_id, context_id, source_id, generation_id)
        REFERENCES kubernetes_inventory_staging(tenant_id, context_id, source_id, generation_id) ON DELETE CASCADE
);

-- A tenant-visible generation is published only after its complete submitted
-- object evidence is retained. Source authority remains on the parent row.
CREATE TABLE IF NOT EXISTS kubernetes_inventory_generations (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    id uuid NOT NULL,
    sender_serial text NOT NULL CHECK (sender_serial ~ '^[0-9a-f]{1,128}$'),
    manifest bytea NOT NULL CHECK (octet_length(manifest) > 0),
    payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
    part_count bigint NOT NULL CHECK (part_count BETWEEN 0 AND 4294967295),
    row_count bigint NOT NULL CHECK (row_count >= 0),
    body_bytes bigint NOT NULL CHECK (body_bytes >= 0),
    retained_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, context_id, source_id, id),
    FOREIGN KEY (tenant_id, context_id, source_id)
        REFERENCES kubernetes_inventory_sources(tenant_id, context_id, id) ON DELETE CASCADE,
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid),
    CHECK (isfinite(retained_at))
);

CREATE TABLE IF NOT EXISTS kubernetes_inventory_windows (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    window_index bigint NOT NULL CHECK (window_index BETWEEN 0 AND 4294967295),
    object_kind smallint NOT NULL CHECK (object_kind BETWEEN 1 AND 10),
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, context_id, source_id, generation_id, window_index),
    UNIQUE (tenant_id, context_id, source_id, generation_id, window_index, object_kind),
    FOREIGN KEY (tenant_id, context_id, source_id, generation_id)
        REFERENCES kubernetes_inventory_generations(tenant_id, context_id, source_id, id) ON DELETE CASCADE,
    CHECK (isfinite(valid_from) AND isfinite(valid_until) AND valid_until > valid_from)
);
CREATE INDEX IF NOT EXISTS kubernetes_inventory_windows_time_idx
    ON kubernetes_inventory_windows(tenant_id, context_id, source_id, valid_until, valid_from);
CREATE INDEX IF NOT EXISTS kubernetes_inventory_flow_overlap_idx
    ON kubernetes_inventory_windows(tenant_id, context_id, valid_until, valid_from)
    WHERE object_kind IN (1,2);
CREATE INDEX IF NOT EXISTS kubernetes_inventory_age_idx
    ON kubernetes_inventory_windows(tenant_id, valid_until);

CREATE TABLE IF NOT EXISTS kubernetes_inventory_objects (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    window_index bigint NOT NULL,
    object_kind smallint NOT NULL,
    object_uid text NOT NULL CHECK (octet_length(object_uid) BETWEEN 1 AND 256),
    object_name text NOT NULL CHECK (octet_length(object_name) BETWEEN 1 AND 253),
    controller_unowned boolean NOT NULL DEFAULT false CHECK (NOT controller_unowned OR object_kind >= 4),
    PRIMARY KEY (tenant_id, context_id, source_id, generation_id, window_index, object_kind, object_uid),
    FOREIGN KEY (tenant_id, context_id, source_id, generation_id, window_index, object_kind)
        REFERENCES kubernetes_inventory_windows(tenant_id, context_id, source_id, generation_id, window_index, object_kind) ON DELETE CASCADE
);

-- Addresses refer to the original object in that exact evidence window. A
-- complete upload can declare the address and original in different parts.
CREATE TABLE IF NOT EXISTS kubernetes_inventory_addresses (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    window_index bigint NOT NULL,
    object_kind smallint NOT NULL CHECK (object_kind IN (1,2)),
    object_uid text NOT NULL,
    ip inet NOT NULL,
    address_text text GENERATED ALWAYS AS (host(ip)) STORED,
    PRIMARY KEY (tenant_id, context_id, source_id, generation_id, window_index, object_kind, object_uid, ip),
    FOREIGN KEY (tenant_id, context_id, source_id, generation_id, window_index, object_kind, object_uid)
        REFERENCES kubernetes_inventory_objects(tenant_id, context_id, source_id, generation_id, window_index, object_kind, object_uid)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    CHECK ((family(ip) = 4 AND masklen(ip) = 32) OR (family(ip) = 6 AND masklen(ip) = 128))
);
CREATE INDEX IF NOT EXISTS kubernetes_inventory_addresses_owner_idx
    ON kubernetes_inventory_addresses(tenant_id, context_id, source_id, ip, generation_id, window_index);

CREATE TABLE IF NOT EXISTS kubernetes_inventory_relationships (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    generation_id uuid NOT NULL,
    window_index bigint NOT NULL,
    witness_kind smallint NOT NULL,
    witness_uid text NOT NULL CHECK (octet_length(witness_uid) BETWEEN 1 AND 256),
    relationship_kind smallint NOT NULL CHECK (relationship_kind IN (1,2)),
    from_kind smallint NOT NULL CHECK (from_kind BETWEEN 1 AND 10),
    from_uid text NOT NULL CHECK (octet_length(from_uid) BETWEEN 1 AND 256),
    to_kind smallint NOT NULL CHECK (to_kind BETWEEN 1 AND 10),
    to_uid text NOT NULL CHECK (octet_length(to_uid) BETWEEN 1 AND 256),
    PRIMARY KEY (tenant_id, context_id, source_id, generation_id, window_index, witness_kind, witness_uid,
                 relationship_kind, from_kind, from_uid, to_kind, to_uid),
    FOREIGN KEY (tenant_id, context_id, source_id, generation_id, window_index, witness_kind, witness_uid)
        REFERENCES kubernetes_inventory_objects(tenant_id, context_id, source_id, generation_id, window_index, object_kind, object_uid)
        ON DELETE CASCADE DEFERRABLE INITIALLY DEFERRED,
    CHECK ((from_kind,from_uid) <> (to_kind,to_uid))
);

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'kubernetes_inventory_sources', 'kubernetes_inventory_staging', 'kubernetes_inventory_stage_parts',
        'kubernetes_inventory_generations', 'kubernetes_inventory_windows', 'kubernetes_inventory_objects',
        'kubernetes_inventory_addresses', 'kubernetes_inventory_relationships'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = NULLIF(current_setting(''probectl.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting(''probectl.tenant_id'', true), '''')::uuid)',
            table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS tenant_write_fence ON %I', table_name);
        EXECUTE format(
            'CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()',
            table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER tenant_write_fence', table_name);
    END LOOP;
END $$;

GRANT SELECT, INSERT, DELETE ON kubernetes_inventory_sources TO probectl_app;
GRANT UPDATE (closed_at) ON kubernetes_inventory_sources TO probectl_app;
GRANT SELECT, INSERT, DELETE ON kubernetes_inventory_staging, kubernetes_inventory_stage_parts TO probectl_app;
GRANT UPDATE (next_part, appended_rows, appended_bytes) ON kubernetes_inventory_staging TO probectl_app;
GRANT SELECT, INSERT, DELETE ON kubernetes_inventory_generations, kubernetes_inventory_windows, kubernetes_inventory_objects,
    kubernetes_inventory_addresses, kubernetes_inventory_relationships TO probectl_app;
