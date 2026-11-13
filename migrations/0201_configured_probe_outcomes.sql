-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Optional outcomes reuse the existing sender-bound evidence retention.
-- lock-ok: nullable columns and NOT VALID replacement checks avoid scanning
-- historical evidence while holding the DDL lock. Legacy rows remain absent.
CREATE OR REPLACE FUNCTION public.probectl_probe_outcome_valid(document jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE field_name text;
BEGIN
    IF document IS NULL THEN RETURN true; END IF;
    IF jsonb_typeof(document)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(document))<>7 THEN RETURN false; END IF;
    IF document->'version' IS DISTINCT FROM '1'::jsonb
       OR jsonb_typeof(document->'definition_hash') IS DISTINCT FROM 'string'
       OR (document->>'definition_hash') !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(document->'canary_type') IS DISTINCT FROM 'string'
       OR (document->>'canary_type') !~ '^[a-z0-9_-]{1,128}$'
       OR document->>'canary_type'='icmp' THEN RETURN false; END IF;
    FOREACH field_name IN ARRAY ARRAY['success','canceled'] LOOP
        IF jsonb_typeof(document->field_name) IS DISTINCT FROM 'boolean' THEN RETURN false; END IF;
    END LOOP;
    FOREACH field_name IN ARRAY ARRAY['started_at','completed_at'] LOOP
        IF jsonb_typeof(document->field_name) IS DISTINCT FROM 'string'
           OR (document->>field_name) !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$' THEN RETURN false; END IF;
    END LOOP;
    RETURN (document->>'completed_at')::timestamptz >= (document->>'started_at')::timestamptz;
EXCEPTION WHEN invalid_text_representation OR invalid_datetime_format OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END $$;

CREATE OR REPLACE FUNCTION public.probectl_install_probe_outcomes(target_schema text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE target regclass; relation text;
BEGIN
    IF target_schema IS NULL OR target_schema !~ '^(public|t_[0-9a-f]{32})$' THEN
        RAISE EXCEPTION 'unsupported outcome evidence schema' USING ERRCODE='23514';
    END IF;
    relation=format('%I.entity_evidence',target_schema);
    target=to_regclass(relation);
    IF target IS NULL THEN RAISE EXCEPTION 'evidence relation is missing' USING ERRCODE='23514'; END IF;
    EXECUTE format('ALTER TABLE %s ADD COLUMN IF NOT EXISTS probe_outcome jsonb DEFAULT NULL',relation);
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=target AND conname='entity_evidence_alias_kind_v2_check') THEN
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_evidence_alias_kind_v2_check CHECK
            (alias_kind IN (''address'',''prefix'',''snmp_device_id'',''snmp_interface_id'',''physical_neighbor_id'',
             ''flow_exporter_id'',''bmp_peer_id'',''path_hop_id'',''configured_test_id'',''agent_site_id'',
             ''site_key'',''customer_key'',''service_key'')) NOT VALID',relation);
    END IF;
    -- Install the complete typed boundary before removing the former enum.
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=target AND conname='entity_evidence_probe_outcome_check') THEN
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_evidence_probe_outcome_check CHECK
            ((probe_outcome IS NULL AND alias_kind<>''configured_test_id'') OR
             (probe_outcome IS NOT NULL AND icmp_measurement IS NULL AND source_kind=''path_agent''
              AND alias_kind=''configured_test_id'' AND source_ref=''probe:configured-test''
              AND alias_value=configured_ref AND configured_ref<>''00000000-0000-0000-0000-000000000000''
              AND configured_ref ~ ''^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$''
              AND public.probectl_probe_outcome_valid(probe_outcome)
              AND observed_at=(probe_outcome->>''completed_at'')::timestamptz)) NOT VALID',relation);
    END IF;
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT IF EXISTS entity_evidence_alias_kind_check',relation);
END $$;

DO $$
DECLARE schema_name text;
BEGIN
    FOR schema_name IN SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relname='entity_evidence' AND c.relkind='r'
          AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        PERFORM public.probectl_install_probe_outcomes(schema_name);
    END LOOP;
END $$;
