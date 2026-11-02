-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-3: typed, tenant-owned tag state. The FK target indexes on the existing
-- identity tables were built online by 0155 before this transactional change.

CREATE TABLE IF NOT EXISTS entity_test_contexts (
    tenant_id uuid NOT NULL,
    test_id uuid NOT NULL,
    context_id uuid NOT NULL,
    assigned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, test_id),
    UNIQUE (tenant_id, test_id, context_id),
    FOREIGN KEY (tenant_id, test_id)
        REFERENCES tests(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id)
        REFERENCES entity_contexts(tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS entity_test_contexts_context_idx
    ON entity_test_contexts(tenant_id, context_id, test_id);
INSERT INTO entity_test_contexts(tenant_id, test_id, context_id)
SELECT tenant_id, test_id, context_id FROM entity_path_test_contexts
ON CONFLICT (tenant_id, test_id) DO NOTHING;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='entity_path_test_contexts'::regclass
                     AND conname='entity_path_general_context_fk') THEN
        ALTER TABLE entity_path_test_contexts
            ADD CONSTRAINT entity_path_general_context_fk
            FOREIGN KEY (tenant_id, test_id, context_id)
            REFERENCES entity_test_contexts(tenant_id, test_id, context_id)
            ON DELETE CASCADE;
    END IF;
END $$;
CREATE OR REPLACE FUNCTION public.entity_clear_test_context_on_retarget()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.target IS DISTINCT FROM OLD.target THEN
        EXECUTE format('DELETE FROM %I.entity_test_contexts WHERE tenant_id=$1 AND test_id=$2',
                       TG_TABLE_SCHEMA)
            USING OLD.tenant_id, OLD.id;
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS entity_test_retarget ON tests;
CREATE TRIGGER entity_test_retarget AFTER UPDATE OF target ON tests
    FOR EACH ROW EXECUTE FUNCTION public.entity_clear_test_context_on_retarget();
ALTER TABLE tests ENABLE ALWAYS TRIGGER entity_test_retarget;

CREATE TABLE IF NOT EXISTS tenant_tag_revisions (
    tenant_id uuid PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    revision bigint NOT NULL DEFAULT 1 CHECK (revision > 0),
    changed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS tenant_tag_definitions (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    key text NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{0,63}$'
                             AND key !~ '^probectl_'
                             AND key NOT IN (
                                 'tenant_id','agent_id','bytes','packets','flows',
                                 'exporter','obs_domain','protocol','ts','start_ts',
                                 'src_addr','dst_addr','src_port','dst_port',
                                 'transport','net_type','in_if','out_if','vlan',
                                 'tos','tcp_flags','next_hop','raw_bytes',
                                 'raw_packets','sampling','bytes_scaled',
                                 'packets_scaled','src_asn','src_as_name',
                                 'src_country','dst_asn','dst_as_name',
                                 'dst_country','row_id','src_prefix','dst_prefix',
                                 'dscp','tcp_flag_names','in_if_name','out_if_name')),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, key),
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid)
);

CREATE TABLE IF NOT EXISTS tenant_tag_assignments (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL,
    tag_id uuid NOT NULL,
    target_kind text NOT NULL CHECK (target_kind IN
        ('device','interface','prefix','exporter','agent','test')),
    entity_id uuid,
    entity_kind text,
    agent_id text,
    test_id uuid,
    exporter_agent_id text,
    exporter_source_kind text,
    exporter_source_ref text,
    value text NOT NULL CHECK (octet_length(value) BETWEEN 1 AND 128
                               AND value !~ '[[:cntrl:]]'),
    source text NOT NULL CHECK (source IN ('manual','netbox')),
    source_ref text CHECK (source_ref IS NULL OR
        (octet_length(source_ref) BETWEEN 1 AND 128 AND
         source_ref ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$')),
    reviewed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, context_id, id),
    FOREIGN KEY (tenant_id, tag_id)
        REFERENCES tenant_tag_definitions(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id)
        REFERENCES entity_contexts(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id, entity_id, entity_kind)
        REFERENCES entities(tenant_id, context_id, id, kind) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, agent_id, context_id)
        REFERENCES entity_agent_contexts(tenant_id, agent_id, context_id)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, test_id, context_id)
        REFERENCES entity_test_contexts(tenant_id, test_id, context_id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id, exporter_agent_id,
                 exporter_source_kind, exporter_source_ref)
        REFERENCES entity_source_contexts
            (tenant_id, context_id, agent_id, source_kind, source_ref)
        ON UPDATE RESTRICT ON DELETE CASCADE,
    CHECK ((source='manual' AND source_ref IS NULL AND reviewed_at IS NULL) OR
           (source='netbox' AND source_ref IS NOT NULL AND reviewed_at IS NOT NULL)),
    CHECK (
        (target_kind IN ('device','interface','prefix') AND entity_id IS NOT NULL
         AND entity_kind IS NOT NULL AND entity_kind=target_kind
         AND agent_id IS NULL AND test_id IS NULL
         AND exporter_agent_id IS NULL AND exporter_source_kind IS NULL
         AND exporter_source_ref IS NULL) OR
        (target_kind='agent' AND agent_id IS NOT NULL AND entity_id IS NULL
         AND entity_kind IS NULL AND test_id IS NULL
         AND exporter_agent_id IS NULL AND exporter_source_kind IS NULL
         AND exporter_source_ref IS NULL) OR
        (target_kind='test' AND test_id IS NOT NULL AND entity_id IS NULL
         AND entity_kind IS NULL AND agent_id IS NULL
         AND exporter_agent_id IS NULL AND exporter_source_kind IS NULL
         AND exporter_source_ref IS NULL) OR
        (target_kind='exporter' AND exporter_agent_id IS NOT NULL
         AND exporter_source_kind IS NOT NULL
         AND exporter_source_kind='flow_exporter' AND exporter_source_ref IS NOT NULL
         AND entity_id IS NULL AND entity_kind IS NULL
         AND agent_id IS NULL AND test_id IS NULL)
    ),
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid)
);
CREATE UNIQUE INDEX IF NOT EXISTS tenant_tag_assignment_entity_uidx
    ON tenant_tag_assignments(tenant_id,context_id,tag_id,entity_id,source)
    WHERE entity_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS tenant_tag_assignment_agent_uidx
    ON tenant_tag_assignments(tenant_id,context_id,tag_id,agent_id,source)
    WHERE agent_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS tenant_tag_assignment_test_uidx
    ON tenant_tag_assignments(tenant_id,context_id,tag_id,test_id,source)
    WHERE test_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS tenant_tag_assignment_exporter_uidx
    ON tenant_tag_assignments
        (tenant_id,context_id,tag_id,exporter_agent_id,exporter_source_ref,source)
    WHERE exporter_agent_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS tenant_tag_assignments_tag_idx
    ON tenant_tag_assignments(tenant_id, tag_id, context_id, id);

CREATE TABLE IF NOT EXISTS tenant_tag_rules (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL,
    tag_id uuid NOT NULL,
    target_kind text NOT NULL CHECK (target_kind IN
        ('device','interface','prefix','exporter','agent','test')),
    match_kind text NOT NULL CHECK (match_kind IN ('cidr','name_pattern','snmp_field')),
    address_side text,
    cidr cidr,
    name_pattern text,
    snmp_field text,
    snmp_value text,
    value text NOT NULL CHECK (octet_length(value) BETWEEN 1 AND 128
                               AND value !~ '[[:cntrl:]]'),
    priority integer NOT NULL DEFAULT 0 CHECK (priority BETWEEN -1000 AND 1000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, context_id, id),
    FOREIGN KEY (tenant_id, tag_id)
        REFERENCES tenant_tag_definitions(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id)
        REFERENCES entity_contexts(tenant_id, id) ON DELETE CASCADE,
    CHECK ((match_kind='cidr' AND address_side IS NOT NULL AND address_side IN
             ('src','dst','exporter','interface','device') AND cidr IS NOT NULL
             AND name_pattern IS NULL AND snmp_field IS NULL AND snmp_value IS NULL) OR
           (match_kind='name_pattern' AND name_pattern IS NOT NULL
             AND octet_length(name_pattern) BETWEEN 1 AND 256
             AND address_side IS NULL AND cidr IS NULL
             AND snmp_field IS NULL AND snmp_value IS NULL) OR
           (match_kind='snmp_field' AND snmp_field IS NOT NULL AND snmp_field IN
             ('sys_name','sys_descr','if_name','if_descr')
             AND snmp_value IS NOT NULL AND octet_length(snmp_value) BETWEEN 1 AND 256
             AND address_side IS NULL AND cidr IS NULL AND name_pattern IS NULL)),
    CHECK (id <> '00000000-0000-0000-0000-000000000000'::uuid)
);
CREATE INDEX IF NOT EXISTS tenant_tag_rules_lookup_idx
    ON tenant_tag_rules(tenant_id, context_id, target_kind, match_kind, tag_id, id);

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'entity_test_contexts','tenant_tag_revisions','tenant_tag_definitions',
        'tenant_tag_assignments','tenant_tag_rules'
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
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO probectl_app', table_name);
    END LOOP;
END $$;

-- Statement-level transition tables make one bulk import advance the tenant
-- revision once, in the same transaction as the accepted metadata change.
-- Exporter and agent-context ownership also shape tenant-wide tag results,
-- so their edits must invalidate revision-pinned cursors.
CREATE OR REPLACE FUNCTION public.tenant_tags_bump_revision()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        -- An empty tag set reads as revision 1. Its first accepted write
        -- must become 2 so a saved cursor cannot treat both sets as equal.
        EXECUTE format('INSERT INTO %I.tenant_tag_revisions(tenant_id,revision,changed_at) SELECT DISTINCT tenant_id,2,clock_timestamp() FROM tag_new_rows ON CONFLICT (tenant_id) DO UPDATE SET revision=tenant_tag_revisions.revision+1,changed_at=clock_timestamp()',
                       TG_TABLE_SCHEMA);
    ELSIF TG_OP = 'UPDATE' THEN
        EXECUTE format('UPDATE %I.tenant_tag_revisions r SET revision=r.revision+1,changed_at=clock_timestamp() FROM (SELECT DISTINCT tenant_id FROM tag_new_rows) changed WHERE r.tenant_id=changed.tenant_id',
                       TG_TABLE_SCHEMA);
    ELSE
        -- Parent tenant deletion cascades to tag rows. Do not reinsert a
        -- revision row whose tenant was just deleted; ordinary tag deletes
        -- still advance the extant tenant's revision atomically.
        EXECUTE format('UPDATE %I.tenant_tag_revisions r SET revision=r.revision+1,changed_at=clock_timestamp() FROM (SELECT DISTINCT tenant_id FROM tag_old_rows) changed WHERE r.tenant_id=changed.tenant_id',
                       TG_TABLE_SCHEMA);
    END IF;
    RETURN NULL;
END $$;
DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'entity_test_contexts','entity_agent_contexts',
        'entity_source_contexts','tenant_tag_definitions',
        'tenant_tag_assignments','tenant_tag_rules'
    ] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS tenant_tag_revision_insert ON %I', table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS tenant_tag_revision_update ON %I', table_name);
        EXECUTE format('DROP TRIGGER IF EXISTS tenant_tag_revision_delete ON %I', table_name);
        EXECUTE format(
            'CREATE TRIGGER tenant_tag_revision_insert AFTER INSERT ON %I REFERENCING NEW TABLE AS tag_new_rows FOR EACH STATEMENT EXECUTE FUNCTION public.tenant_tags_bump_revision()',
            table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER tenant_tag_revision_insert', table_name);
        EXECUTE format(
            'CREATE TRIGGER tenant_tag_revision_update AFTER UPDATE ON %I REFERENCING NEW TABLE AS tag_new_rows FOR EACH STATEMENT EXECUTE FUNCTION public.tenant_tags_bump_revision()',
            table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER tenant_tag_revision_update', table_name);
        EXECUTE format(
            'CREATE TRIGGER tenant_tag_revision_delete AFTER DELETE ON %I REFERENCING OLD TABLE AS tag_old_rows FOR EACH STATEMENT EXECUTE FUNCTION public.tenant_tags_bump_revision()',
            table_name);
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER tenant_tag_revision_delete', table_name);
    END LOOP;
END $$;
