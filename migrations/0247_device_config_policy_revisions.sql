-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Rules are scoped to a canonical device and stored as immutable revisions.
-- There is no archive content in this table.
DO $device_policy$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT n.nspname AS schema_name
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
         WHERE c.relname='entities' AND c.relkind IN ('r','p')
           AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        EXECUTE format('CREATE TABLE IF NOT EXISTS %I.device_config_policy_revisions (
            tenant_id uuid NOT NULL,
            context_id uuid NOT NULL,
            device_entity_id uuid NOT NULL,
            version bigint NOT NULL CHECK (version > 0),
            rules jsonb NOT NULL CHECK (jsonb_typeof(rules)=''array'' AND octet_length(rules::text)<=131072),
            published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (tenant_id, context_id, device_entity_id, version),
            CONSTRAINT device_config_policy_device_fk FOREIGN KEY (tenant_id, context_id, device_entity_id)
                REFERENCES %I.entities(tenant_id, context_id, id) ON DELETE CASCADE
        )',target.schema_name,target.schema_name);
        EXECUTE format('ALTER TABLE %I.device_config_policy_revisions ENABLE ROW LEVEL SECURITY',target.schema_name);
        EXECUTE format('ALTER TABLE %I.device_config_policy_revisions FORCE ROW LEVEL SECURITY',target.schema_name);
        EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I.device_config_policy_revisions',target.schema_name);
        EXECUTE format('CREATE POLICY tenant_isolation ON %I.device_config_policy_revisions
            USING (tenant_id=NULLIF(current_setting(''probectl.tenant_id'',true),'''')::uuid)
            WITH CHECK (tenant_id=NULLIF(current_setting(''probectl.tenant_id'',true),'''')::uuid)',target.schema_name);
        EXECUTE format('DROP TRIGGER IF EXISTS tenant_write_fence ON %I.device_config_policy_revisions',target.schema_name);
        EXECUTE format('CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON %I.device_config_policy_revisions
            FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()',target.schema_name);
        EXECUTE format('ALTER TABLE %I.device_config_policy_revisions ENABLE ALWAYS TRIGGER tenant_write_fence',target.schema_name);
        EXECUTE format('REVOKE UPDATE ON %I.device_config_policy_revisions FROM probectl_app',target.schema_name);
        EXECUTE format('REVOKE ALL ON %I.device_config_policy_revisions FROM probectl_provider',target.schema_name);
        EXECUTE format('GRANT SELECT,INSERT,DELETE ON %I.device_config_policy_revisions TO probectl_app',target.schema_name);
    END LOOP;
END;
$device_policy$;
