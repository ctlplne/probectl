-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-2b: operator-owned NMS imports have their own provenance. They cannot
-- author mTLS agent evidence or choose a routing context from a source row.
CREATE TABLE IF NOT EXISTS nms_import_sources (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL,
    source_kind text NOT NULL CHECK (source_kind IN ('librenms', 'zabbix', 'orion', 'prtg')),
    instance_ref text NOT NULL CHECK (octet_length(instance_ref) BETWEEN 1 AND 128
                                      AND instance_ref ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, context_id, id),
    UNIQUE (tenant_id, context_id, source_kind, instance_ref),
    FOREIGN KEY (tenant_id, context_id)
        REFERENCES entity_contexts(tenant_id, id) ON DELETE CASCADE,
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid)
);
CREATE INDEX IF NOT EXISTS nms_import_sources_tenant_kind_idx
    ON nms_import_sources(tenant_id, context_id, source_kind, id);

-- Only a normalized, redacted snapshot is persisted. A plan expires and its
-- exact content hash is checked again by apply; preview itself changes no
-- canonical entity, alert rule, agent or credential.
CREATE TABLE IF NOT EXISTS nms_import_plans (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL,
    source_id uuid NOT NULL,
    snapshot_hash text NOT NULL CHECK (snapshot_hash ~ '^[0-9a-f]{64}$'),
    source_generation_hash text NOT NULL CHECK (source_generation_hash ~ '^[0-9a-f]{64}$'),
    policy_version integer NOT NULL CHECK (policy_version > 0),
    row_count bigint NOT NULL CHECK (row_count >= 0),
    state text NOT NULL DEFAULT 'capturing' CHECK (state IN ('capturing', 'sealed', 'preview', 'applying', 'applied', 'stale')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, context_id, id),
    UNIQUE (tenant_id, context_id, id, source_id),
    FOREIGN KEY (tenant_id, context_id, source_id)
        REFERENCES nms_import_sources(tenant_id, context_id, id) ON DELETE CASCADE,
    CHECK (expires_at > created_at),
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid)
);
CREATE INDEX IF NOT EXISTS nms_import_plans_tenant_source_idx
    ON nms_import_plans(tenant_id, context_id, source_id, created_at DESC, id);

-- One committed page receipt per capture ordinal. The service inserts this
-- alongside its normalized rows in a tenant transaction, using a hash of
-- normalized fields only. A retry can compare that hash without persisting
-- raw vendor JSON, credentials, URLs or pagination links. No row or source
-- address can select a destination context.
CREATE TABLE IF NOT EXISTS nms_import_pages (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    page_number bigint NOT NULL CHECK (page_number >= 0),
    resource_kind text NOT NULL CHECK (resource_kind IN ('devices', 'locations', 'nodes', 'groups', 'memberships', 'rules', 'hosts', 'probes')),
    first_row bigint NOT NULL CHECK (first_row >= 0),
    row_count bigint NOT NULL CHECK (row_count >= 0),
    page_hash text NOT NULL CHECK (page_hash ~ '^[0-9a-f]{64}$'),
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, context_id, plan_id, page_number),
    FOREIGN KEY (tenant_id, context_id, plan_id)
        REFERENCES nms_import_plans(tenant_id, context_id, id) ON DELETE CASCADE,
    CHECK (first_row <= 9223372036854775807 - row_count)
);

-- The application validates these fields against a fixed allowlist before
-- insert. Raw source JSON, rules, macros, passwords and notification targets
-- have no destination column. A target entity must be in this exact context.
CREATE TABLE IF NOT EXISTS nms_import_rows (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    row_number bigint NOT NULL CHECK (row_number >= 0),
    object_kind text NOT NULL CHECK (object_kind IN ('device', 'site', 'group', 'membership', 'poll_setting', 'alert_rule')),
    external_id text NOT NULL CHECK (octet_length(external_id) BETWEEN 1 AND 256),
    label text CHECK (label IS NULL OR octet_length(label) BETWEEN 1 AND 256),
    address text CHECK (address IS NULL OR octet_length(address) BETWEEN 1 AND 255),
    hostname text CHECK (hostname IS NULL OR octet_length(hostname) BETWEEN 1 AND 253),
    parent_external_id text CHECK (parent_external_id IS NULL OR
                                   (octet_length(parent_external_id) BETWEEN 1 AND 256 AND parent_external_id ~ '^[0-9a-f]+$')),
    location_id text CHECK (location_id IS NULL OR
                            (octet_length(location_id) BETWEEN 1 AND 256 AND location_id ~ '^[0-9a-f]+$')),
    location_label text CHECK (location_label IS NULL OR octet_length(location_label) BETWEEN 1 AND 256),
    group_ids text[] NOT NULL DEFAULT '{}'::text[]
        CHECK (cardinality(group_ids) <= 256
               AND array_position(group_ids, NULL) IS NULL
               AND octet_length(array_to_string(group_ids, ',')) <= 65536
               AND array_to_string(group_ids, ',') ~ '^[0-9a-f,]*$'),
    poll_seconds bigint CHECK (poll_seconds IS NULL OR poll_seconds BETWEEN 1 AND 604800),
    severity text CHECK (severity IS NULL OR severity IN ('ok', 'warning', 'critical')),
    target_entity_id uuid,
    action text NOT NULL DEFAULT 'captured'
        CHECK (action IN ('captured', 'create', 'update', 'conflict', 'skip', 'unmapped')),
    unmapped_codes text[] NOT NULL DEFAULT '{}'::text[]
        CHECK (cardinality(unmapped_codes) <= 32
               AND array_position(unmapped_codes, NULL) IS NULL
               AND octet_length(array_to_string(unmapped_codes, ',')) <= 1024
               AND array_to_string(unmapped_codes, ',') ~ '^[a-z_,]*$'),
    state text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'applied', 'skipped')),
    applied_at timestamptz,
    PRIMARY KEY (tenant_id, context_id, plan_id, row_number),
    UNIQUE (tenant_id, context_id, plan_id, object_kind, external_id),
    FOREIGN KEY (tenant_id, context_id, plan_id)
        REFERENCES nms_import_plans(tenant_id, context_id, id) ON DELETE CASCADE,
    -- A removed target invalidates the old plan row and its hash. Cascading
    -- also lets full-tenant erasure delete entities and plans in one transaction
    -- without an ON DELETE SET NULL update after the tenant write fence closes.
    FOREIGN KEY (tenant_id, context_id, target_entity_id)
        REFERENCES entities(tenant_id, context_id, id) ON DELETE CASCADE,
    CHECK ((state = 'applied') = (applied_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS nms_import_rows_tenant_state_idx
    ON nms_import_rows(tenant_id, context_id, plan_id, state, row_number);

-- This is an operator import binding, not a claim of observed telemetry.
CREATE TABLE IF NOT EXISTS nms_import_provenance (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    object_kind text NOT NULL CHECK (object_kind IN ('device', 'site')),
    external_id text NOT NULL CHECK (octet_length(external_id) BETWEEN 1 AND 256),
    entity_id uuid NOT NULL,
    plan_id uuid NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, context_id, source_id, object_kind, external_id),
    FOREIGN KEY (tenant_id, context_id, source_id)
        REFERENCES nms_import_sources(tenant_id, context_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id, plan_id, source_id)
        REFERENCES nms_import_plans(tenant_id, context_id, id, source_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, context_id, plan_id, object_kind, external_id)
        REFERENCES nms_import_rows(tenant_id, context_id, plan_id, object_kind, external_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, context_id, entity_id)
        REFERENCES entities(tenant_id, context_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS nms_import_provenance_tenant_entity_idx
    ON nms_import_provenance(tenant_id, context_id, entity_id);

DO $nms_import_rls$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'nms_import_sources', 'nms_import_plans', 'nms_import_pages', 'nms_import_rows',
        'nms_import_provenance'
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
END $nms_import_rls$;
