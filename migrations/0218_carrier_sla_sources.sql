-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Immutable financial revisions keep the operator's selectors. These live
-- references are derived from canonical tenant assignments, never addresses.
-- Retiring a source removes the reference while preserving the contract.
CREATE TABLE IF NOT EXISTS flow_capacity_agreement_sla_refs (
    tenant_id uuid NOT NULL,
    agreement_id uuid NOT NULL,
    version bigint NOT NULL,
    agent_id text NOT NULL,
    test_id uuid NOT NULL,
    context_id uuid NOT NULL,
    device_id uuid NOT NULL,
    source_assigned_at timestamptz NOT NULL,
    source_kind text GENERATED ALWAYS AS ('path_agent'::text) STORED,
    source_ref text GENERATED ALWAYS AS (test_id::text) STORED,
    device_kind text GENERATED ALWAYS AS ('device'::text) STORED,
    PRIMARY KEY (tenant_id,agreement_id,version,agent_id,test_id),
    FOREIGN KEY (tenant_id,agreement_id,version)
        REFERENCES flow_capacity_agreement_revisions(tenant_id,agreement_id,version) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,agent_id,source_kind,source_ref)
        REFERENCES entity_source_contexts(tenant_id,agent_id,source_kind,source_ref) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,test_id) REFERENCES tests(tenant_id,id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id,context_id,device_id,device_kind)
        REFERENCES entities(tenant_id,context_id,id,kind) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS flow_capacity_sla_test_idx
    ON flow_capacity_agreement_sla_refs(tenant_id,test_id,agent_id);

CREATE OR REPLACE FUNCTION public.probectl_capacity_sla_references()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE selection jsonb; selected_agent text; selected_test uuid;
        selected_context uuid; selected_device uuid; selected_epoch timestamptz;
BEGIN
    IF NEW.definition->'sla'->'sources' IS NULL THEN
        RETURN NEW;
    END IF;
    IF jsonb_typeof(NEW.definition->'sla'->'sources')<>'array' THEN
        RAISE EXCEPTION 'invalid carrier source selection' USING ERRCODE='23514';
    END IF;
    FOR selection IN SELECT jsonb_array_elements(NEW.definition->'sla'->'sources') LOOP
        selected_agent:=selection->>'agent_id';
        selected_test:=(selection->>'test_id')::uuid;
        EXECUTE format('SELECT m.context_id,m.anchor_entity_id,m.assigned_at
            FROM %I.entity_source_contexts m
            JOIN %I.entity_test_contexts c ON c.tenant_id=m.tenant_id
                AND c.test_id=$3 AND c.context_id=m.context_id
            JOIN %I.entities e ON e.tenant_id=m.tenant_id
                AND e.context_id=m.context_id AND e.id=m.anchor_entity_id AND e.kind=''device''
            WHERE m.tenant_id=$1 AND m.agent_id=$2 AND m.source_kind=''path_agent''
                AND m.source_ref=$3::text AND m.assigned_at<=transaction_timestamp()
                AND (m.expires_at IS NULL OR m.expires_at>transaction_timestamp())',
            TG_TABLE_SCHEMA,TG_TABLE_SCHEMA,TG_TABLE_SCHEMA)
            INTO selected_context,selected_device,selected_epoch
            USING NEW.tenant_id,selected_agent,selected_test;
        IF selected_context IS NULL OR selected_device IS NULL OR selected_epoch IS NULL THEN
            RAISE EXCEPTION 'carrier source selection is unavailable' USING ERRCODE='23503';
        END IF;
        EXECUTE format('INSERT INTO %I.flow_capacity_agreement_sla_refs
            (tenant_id,agreement_id,version,agent_id,test_id,context_id,device_id,source_assigned_at)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)',TG_TABLE_SCHEMA)
            USING NEW.tenant_id,NEW.agreement_id,NEW.version,selected_agent,selected_test,
                selected_context,selected_device,selected_epoch;
    END LOOP;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS capacity_agreement_sla_references ON flow_capacity_agreement_revisions;
CREATE TRIGGER capacity_agreement_sla_references AFTER INSERT ON flow_capacity_agreement_revisions
    FOR EACH ROW EXECUTE FUNCTION public.probectl_capacity_sla_references();
ALTER TABLE flow_capacity_agreement_revisions ENABLE ALWAYS TRIGGER capacity_agreement_sla_references;

ALTER TABLE flow_capacity_agreement_sla_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE flow_capacity_agreement_sla_refs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_isolation ON flow_capacity_agreement_sla_refs;
CREATE POLICY tenant_isolation ON flow_capacity_agreement_sla_refs
    USING (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid)
    WITH CHECK (tenant_id=NULLIF(current_setting('probectl.tenant_id',true),'')::uuid);
DROP TRIGGER IF EXISTS tenant_write_fence ON flow_capacity_agreement_sla_refs;
CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON flow_capacity_agreement_sla_refs
    FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence();
ALTER TABLE flow_capacity_agreement_sla_refs ENABLE ALWAYS TRIGGER tenant_write_fence;
REVOKE ALL ON flow_capacity_agreement_sla_refs FROM probectl_app,probectl_provider;
GRANT SELECT,INSERT,DELETE ON flow_capacity_agreement_sla_refs TO probectl_app;
