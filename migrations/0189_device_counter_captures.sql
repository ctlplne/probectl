-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- A delayed authenticated poll cannot repopulate erased source data. Retain
-- the lifecycle cutoff on both entry and exit, including existing silo copies.
ALTER TABLE flow_snapshot_epochs ADD COLUMN IF NOT EXISTS observation_not_before
    timestamptz NOT NULL DEFAULT '-infinity';
UPDATE flow_snapshot_epochs SET observation_not_before=clock_timestamp()
    WHERE observation_not_before='-infinity' AND (generation>1 OR invalidating);
CREATE OR REPLACE FUNCTION public.probectl_source_observation_fence()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP='INSERT' THEN
        IF NEW.invalidating THEN NEW.observation_not_before=clock_timestamp(); END IF;
    ELSIF NEW.generation IS DISTINCT FROM OLD.generation OR
          (NEW.invalidating AND NOT OLD.invalidating) THEN
        NEW.observation_not_before=GREATEST(OLD.observation_not_before,clock_timestamp());
    ELSE
        NEW.observation_not_before=OLD.observation_not_before;
    END IF;
    RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS source_observation_fence ON flow_snapshot_epochs;
CREATE TRIGGER source_observation_fence BEFORE INSERT OR UPDATE ON flow_snapshot_epochs
    FOR EACH ROW EXECUTE FUNCTION public.probectl_source_observation_fence();
ALTER TABLE flow_snapshot_epochs ENABLE ALWAYS TRIGGER source_observation_fence;

-- First receipts are hash-only tombstones: deleting payloads must not allow
-- an identical late witness to bind its old bytes to a new source incarnation.
CREATE TABLE IF NOT EXISTS device_counter_captures (
    tenant_id uuid NOT NULL,
    capture_key bytea NOT NULL CHECK (octet_length(capture_key)=32),
    captured_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    charged_bytes bigint GENERATED ALWAYS AS (256::bigint) STORED,
    PRIMARY KEY (tenant_id,capture_key),
    CONSTRAINT fx6_counter_capture_tenant_fk FOREIGN KEY (tenant_id)
        REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS device_counter_capture_sources (
    tenant_id uuid NOT NULL,
    capture_key bytea NOT NULL CHECK (octet_length(capture_key)=32),
    context_id uuid NOT NULL,
    device_id uuid NOT NULL,
    device_kind text GENERATED ALWAYS AS ('device'::text) STORED,
    agent_id text NOT NULL CHECK (octet_length(agent_id) BETWEEN 1 AND 128),
    source_kind text GENERATED ALWAYS AS ('device_target'::text) STORED,
    source_ref text NOT NULL CHECK (octet_length(source_ref) BETWEEN 1 AND 1024),
    sender_serial text NOT NULL CHECK (octet_length(sender_serial) BETWEEN 1 AND 256),
    source_assigned_at timestamptz NOT NULL,
    agent_assigned_at timestamptz NOT NULL,
    raw_digest bytea NOT NULL CHECK (octet_length(raw_digest)=32),
    poll_started_unix_nanos bigint NOT NULL CHECK (poll_started_unix_nanos>0),
    poll_completed_unix_nanos bigint NOT NULL CHECK (poll_completed_unix_nanos>=poll_started_unix_nanos),
    point_count bigint NOT NULL CHECK (point_count BETWEEN 1 AND 4294967295),
    charged_bytes bigint GENERATED ALWAYS AS (4096::bigint) STORED,
    PRIMARY KEY (tenant_id,capture_key),
    CONSTRAINT fx6_counter_source_capture_fk FOREIGN KEY (tenant_id,capture_key)
        REFERENCES device_counter_captures(tenant_id,capture_key) ON DELETE CASCADE,
    CONSTRAINT fx6_counter_source_device_fk FOREIGN KEY (tenant_id,context_id,device_id,device_kind)
        REFERENCES entities(tenant_id,context_id,id,kind) ON DELETE CASCADE,
    CONSTRAINT fx6_counter_source_assignment_fk FOREIGN KEY (tenant_id,context_id,agent_id,source_kind,source_ref)
        REFERENCES entity_source_contexts(tenant_id,context_id,agent_id,source_kind,source_ref) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS device_counter_sources_assignment_idx
    ON device_counter_capture_sources(tenant_id,agent_id,source_kind,source_ref);
CREATE INDEX IF NOT EXISTS device_counter_sources_device_idx
    ON device_counter_capture_sources(tenant_id,context_id,device_id,device_kind);
DO $$ DECLARE table_name text; BEGIN
    FOREACH table_name IN ARRAY ARRAY['device_counter_captures','device_counter_capture_sources'] LOOP
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
