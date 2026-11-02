-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- An imported group is an operator-owned inventory set in one selected
-- routing context. It is neither an agent sender nor FX-2 evidence.
CREATE TABLE IF NOT EXISTS nms_import_groups (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    external_id text NOT NULL CHECK (octet_length(external_id) BETWEEN 1 AND 256),
    object_kind text NOT NULL DEFAULT 'group' CHECK (object_kind = 'group'),
    label text NOT NULL CHECK (octet_length(label) BETWEEN 1 AND 256),
    plan_id uuid NOT NULL,
    dynamic_predicate_unmapped boolean NOT NULL DEFAULT false,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, context_id, source_id, external_id),
    FOREIGN KEY (tenant_id, context_id, source_id)
        REFERENCES nms_import_sources(tenant_id, context_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id, plan_id, source_id)
        REFERENCES nms_import_plans(tenant_id, context_id, id, source_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, context_id, plan_id, object_kind, external_id)
        REFERENCES nms_import_rows(tenant_id, context_id, plan_id, object_kind, external_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX IF NOT EXISTS nms_import_groups_tenant_plan_idx
    ON nms_import_groups(tenant_id, context_id, plan_id, external_id);

-- A member is linked by source device ID to an already applied, exact device
-- provenance. No address or display label selects the destination entity.
CREATE TABLE IF NOT EXISTS nms_import_group_members (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    source_id uuid NOT NULL,
    group_external_id text NOT NULL CHECK (octet_length(group_external_id) BETWEEN 1 AND 256),
    member_external_id text NOT NULL CHECK (octet_length(member_external_id) BETWEEN 1 AND 256),
    member_kind text NOT NULL DEFAULT 'device' CHECK (member_kind = 'device'),
    row_external_id text NOT NULL CHECK (octet_length(row_external_id) BETWEEN 1 AND 256),
    object_kind text NOT NULL DEFAULT 'membership' CHECK (object_kind = 'membership'),
    plan_id uuid NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, context_id, source_id, group_external_id, member_external_id),
    FOREIGN KEY (tenant_id, context_id, source_id, group_external_id)
        REFERENCES nms_import_groups(tenant_id, context_id, source_id, external_id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id, source_id, member_kind, member_external_id)
        REFERENCES nms_import_provenance(tenant_id, context_id, source_id, object_kind, external_id)
        ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, context_id, plan_id, source_id)
        REFERENCES nms_import_plans(tenant_id, context_id, id, source_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED,
    FOREIGN KEY (tenant_id, context_id, plan_id, object_kind, row_external_id)
        REFERENCES nms_import_rows(tenant_id, context_id, plan_id, object_kind, external_id)
        ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX IF NOT EXISTS nms_import_group_members_tenant_plan_idx
    ON nms_import_group_members(tenant_id, context_id, plan_id, group_external_id);

DO $nms_import_groups_rls$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['nms_import_groups', 'nms_import_group_members'] LOOP
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
END $nms_import_groups_rls$;
