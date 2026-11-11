-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Financial terms survive retirement of inventory. Only the normalized live
-- target reference cascades; the agreement and its recorded revisions remain.
CREATE TABLE IF NOT EXISTS flow_capacity_agreements (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id uuid NOT NULL CHECK (id<>'00000000-0000-0000-0000-000000000000'::uuid),
    version bigint NOT NULL CHECK (version>0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,id)
);
CREATE TABLE IF NOT EXISTS flow_capacity_agreement_revisions (
    tenant_id uuid NOT NULL,
    agreement_id uuid NOT NULL,
    version bigint NOT NULL CHECK (version>0),
    definition jsonb NOT NULL CHECK (jsonb_typeof(definition)='object'),
    -- Exact nanoseconds without narrowing the full RFC3339 calendar to the
    -- int64 epoch-nanosecond range or PostgreSQL's microsecond timestamps.
    valid_from_nanos numeric NOT NULL CHECK (scale(valid_from_nanos)=0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,agreement_id,version),
    FOREIGN KEY (tenant_id,agreement_id)
        REFERENCES flow_capacity_agreements(tenant_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS flow_capacity_agreement_effective_idx
    ON flow_capacity_agreement_revisions(tenant_id,agreement_id,valid_from_nanos,version);
CREATE TABLE IF NOT EXISTS flow_capacity_agreement_refs (
    tenant_id uuid NOT NULL,
    agreement_id uuid NOT NULL,
    version bigint NOT NULL,
    target_kind text NOT NULL CHECK (target_kind IN ('interface','circuit')),
    context_id uuid,
    interface_id uuid,
    interface_kind text GENERATED ALWAYS AS
        (CASE WHEN target_kind='interface' THEN 'interface'::text ELSE NULL END) STORED,
    tag_id uuid,
    PRIMARY KEY (tenant_id,agreement_id,version),
    FOREIGN KEY (tenant_id,agreement_id,version)
        REFERENCES flow_capacity_agreement_revisions(tenant_id,agreement_id,version) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,context_id,interface_id,interface_kind)
        REFERENCES entities(tenant_id,context_id,id,kind) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,tag_id)
        REFERENCES tenant_tag_definitions(tenant_id,id) ON DELETE CASCADE,
    CHECK ((target_kind='interface' AND context_id IS NOT NULL AND interface_id IS NOT NULL AND tag_id IS NULL)
        OR (target_kind='circuit' AND context_id IS NULL AND interface_id IS NULL AND tag_id IS NOT NULL))
);

CREATE OR REPLACE FUNCTION public.probectl_capacity_agreement_reference()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE kind text;
BEGIN
    kind:=NEW.definition->'target'->>'kind';
    IF kind NOT IN ('interface','circuit') OR kind IS NULL THEN
        RAISE EXCEPTION 'invalid capacity target kind' USING ERRCODE='23514';
    END IF;
    EXECUTE format('INSERT INTO %I.flow_capacity_agreement_refs
        (tenant_id,agreement_id,version,target_kind,context_id,interface_id,tag_id)
        VALUES($1,$2,$3,$4,$5,$6,$7)',TG_TABLE_SCHEMA)
        USING NEW.tenant_id,NEW.agreement_id,NEW.version,kind,
          CASE WHEN kind='interface' THEN (NEW.definition->'target'->>'context_id')::uuid END,
          CASE WHEN kind='interface' THEN (NEW.definition->'target'->>'interface_id')::uuid END,
          CASE WHEN kind='circuit' THEN (NEW.definition->'target'->>'tag_id')::uuid END;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS capacity_agreement_reference ON flow_capacity_agreement_revisions;
CREATE TRIGGER capacity_agreement_reference AFTER INSERT ON flow_capacity_agreement_revisions
    FOR EACH ROW EXECUTE FUNCTION public.probectl_capacity_agreement_reference();
ALTER TABLE flow_capacity_agreement_revisions ENABLE ALWAYS TRIGGER capacity_agreement_reference;

-- Removing the current subject-bearing revision removes its agreement too;
-- removing an older revision leaves unrelated current terms intact. Inventory
-- retirement deletes only refs and never reaches this revision trigger.
CREATE OR REPLACE FUNCTION public.probectl_capacity_agreement_head_delete()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('DELETE FROM %I.flow_capacity_agreements
        WHERE tenant_id=$1 AND id=$2 AND version=$3',TG_TABLE_SCHEMA)
        USING OLD.tenant_id,OLD.agreement_id,OLD.version;
    RETURN OLD;
END $$;
DROP TRIGGER IF EXISTS capacity_agreement_head_delete ON flow_capacity_agreement_revisions;
CREATE TRIGGER capacity_agreement_head_delete AFTER DELETE ON flow_capacity_agreement_revisions
    FOR EACH ROW EXECUTE FUNCTION public.probectl_capacity_agreement_head_delete();
ALTER TABLE flow_capacity_agreement_revisions ENABLE ALWAYS TRIGGER capacity_agreement_head_delete;

DO $$
DECLARE table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY['flow_capacity_agreements',
        'flow_capacity_agreement_revisions','flow_capacity_agreement_refs'] LOOP
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
        EXECUTE format('REVOKE ALL ON %I FROM probectl_app,probectl_provider',table_name);
        EXECUTE format('GRANT SELECT,INSERT,DELETE ON %I TO probectl_app',table_name);
    END LOOP;
END $$;
GRANT UPDATE ON flow_capacity_agreements TO probectl_app;
