-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Configuration only: no materialized role cache or worker. Operation byte
-- admission belongs to the caller; no fixed rule/ASN population quota is stored.
CREATE TABLE IF NOT EXISTS interface_role_policies (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    id uuid NOT NULL CHECK (id<>'00000000-0000-0000-0000-000000000000'::uuid),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision>0),
    format_version smallint NOT NULL DEFAULT 1 CHECK (format_version=1),
    definition jsonb NOT NULL CHECK (
        jsonb_typeof(definition)='object'
        AND definition ?& ARRAY['provider_asns','customer_asns','description_rules']
        AND definition-ARRAY['provider_asns','customer_asns','description_rules']='{}'::jsonb
        AND jsonb_typeof(definition->'provider_asns')='array'
        AND jsonb_typeof(definition->'customer_asns')='array'
        AND jsonb_typeof(definition->'description_rules')='array'
    ),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,context_id),
    CONSTRAINT fx4_role_policy_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fx4_role_policy_context_fk FOREIGN KEY (tenant_id,context_id)
        REFERENCES entity_contexts(tenant_id,id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS interface_role_overrides (
    tenant_id uuid NOT NULL,
    context_id uuid NOT NULL,
    interface_id uuid NOT NULL,
    entity_kind text NOT NULL DEFAULT 'interface' CHECK (entity_kind='interface'),
    id uuid NOT NULL CHECK (id<>'00000000-0000-0000-0000-000000000000'::uuid),
    revision bigint NOT NULL DEFAULT 1 CHECK (revision>0),
    role text NOT NULL CHECK (role IN
        ('transit','ix_peering','private_peering','customer','backbone','other')),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,context_id,interface_id),
    UNIQUE (tenant_id,context_id,id),
    CONSTRAINT fx4_role_override_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT fx4_role_override_interface_fk FOREIGN KEY (tenant_id,context_id,interface_id,entity_kind)
        REFERENCES entities(tenant_id,context_id,id,kind) ON DELETE CASCADE
);

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['interface_role_policies','interface_role_overrides'] LOOP
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
