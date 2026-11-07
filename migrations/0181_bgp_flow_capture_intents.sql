-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- A private provisional snapshot fixes ingestion time before asynchronous
-- sender evidence arrives. It is never a terminal receipt or reader grant.
-- Only exact authenticated sender evidence may publish the existing immutable
-- terminal receipt. Hash-only intents survive payload erasure as tombstones;
-- their original epoch prevents a late witness reviving erased source data.
CREATE TABLE IF NOT EXISTS bgp_flow_capture_intents (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    flow_key bytea NOT NULL CHECK (octet_length(flow_key)=32),
    source_generation bigint NOT NULL CHECK (source_generation>=0),
    captured_at_unix_nanos bigint NOT NULL CHECK (captured_at_unix_nanos>0),
    charged_bytes bigint GENERATED ALWAYS AS (2048::bigint) STORED,
    PRIMARY KEY (tenant_id,flow_key)
);

CREATE TABLE IF NOT EXISTS bgp_flow_capture_intent_payloads (
    tenant_id uuid NOT NULL,
    flow_key bytea NOT NULL CHECK (octet_length(flow_key)=32),
    facts_digest bytea NOT NULL CHECK (octet_length(facts_digest)=32),
    clocks_digest bytea NOT NULL CHECK (octet_length(clocks_digest)=32),
    facts_kind text GENERATED ALWAYS AS ('routing_facts'::text) STORED,
    clocks_kind text GENERATED ALWAYS AS ('routing_clocks'::text) STORED,
    charged_bytes bigint GENERATED ALWAYS AS (2048::bigint) STORED,
    PRIMARY KEY (tenant_id,flow_key),
    CONSTRAINT fx5_capture_intent_payload_intent_fk FOREIGN KEY (tenant_id,flow_key)
        REFERENCES bgp_flow_capture_intents(tenant_id,flow_key) ON DELETE CASCADE,
    CONSTRAINT fx5_capture_intent_payload_facts_fk FOREIGN KEY (tenant_id,facts_digest,facts_kind)
        REFERENCES bgp_flow_capture_objects(tenant_id,digest,kind) ON DELETE CASCADE,
    CONSTRAINT fx5_capture_intent_payload_clocks_fk FOREIGN KEY (tenant_id,clocks_digest,clocks_kind)
        REFERENCES bgp_flow_capture_objects(tenant_id,digest,kind) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS bgp_flow_capture_intent_payload_facts_idx
    ON bgp_flow_capture_intent_payloads(tenant_id,facts_digest);
CREATE INDEX IF NOT EXISTS bgp_flow_capture_intent_payload_clocks_idx
    ON bgp_flow_capture_intent_payloads(tenant_id,clocks_digest);

DO $$ DECLARE table_name text; BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'bgp_flow_capture_intents','bgp_flow_capture_intent_payloads'
    ] LOOP
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
