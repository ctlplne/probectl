-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Optional collector facts reuse immutable tenant/source evidence and its
-- existing lifecycle. No new authority plane, table or retention subsystem.
-- lock-ok: nullable column and NOT VALID checks do not scan historical rows.
CREATE OR REPLACE FUNCTION public.probectl_icmp_measurement_valid(document jsonb, target_address inet)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE field_name text; responder jsonb; address inet; requested bigint;
    attempted bigint; transmitted bigint; replies bigint; send_errors bigint;
BEGIN
    IF document IS NULL THEN RETURN true; END IF;
    IF jsonb_typeof(document)<>'object' OR (SELECT count(*) FROM jsonb_object_keys(document))<>13 THEN RETURN false; END IF;
    IF document->'version' IS DISTINCT FROM '1'::jsonb
       OR jsonb_typeof(document->'definition_hash') IS DISTINCT FROM 'string'
       OR (document->>'definition_hash') !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
    FOREACH field_name IN ARRAY ARRAY['requested','attempted','transmitted','replies','send_errors'] LOOP
        IF jsonb_typeof(document->field_name) IS DISTINCT FROM 'number'
           OR (document->>field_name) !~ '^(0|[1-9][0-9]{0,9})$'
           OR (document->>field_name)::bigint>4294967295 THEN RETURN false; END IF;
    END LOOP;
    requested=(document->>'requested')::bigint;
    attempted=(document->>'attempted')::bigint;
    transmitted=(document->>'transmitted')::bigint;
    replies=(document->>'replies')::bigint;
    send_errors=(document->>'send_errors')::bigint;
    IF requested=0 OR attempted>requested OR transmitted>attempted OR replies>transmitted OR send_errors<>attempted-transmitted THEN RETURN false; END IF;
    FOREACH field_name IN ARRAY ARRAY['read_complete','canceled','io_failed'] LOOP
        IF jsonb_typeof(document->field_name) IS DISTINCT FROM 'boolean' THEN RETURN false; END IF;
    END LOOP;
    FOREACH field_name IN ARRAY ARRAY['started_at','completed_at'] LOOP
        IF jsonb_typeof(document->field_name) IS DISTINCT FROM 'string'
           OR (document->>field_name) !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$' THEN RETURN false; END IF;
    END LOOP;
    IF (document->>'completed_at')::timestamptz < (document->>'started_at')::timestamptz
       OR jsonb_typeof(document->'responders') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
    IF jsonb_array_length(document->'responders')>replies OR
       (replies>0 AND jsonb_array_length(document->'responders')=0 AND document->'io_failed'='false'::jsonb) THEN RETURN false; END IF;
    FOR responder IN SELECT value FROM jsonb_array_elements(document->'responders') LOOP
        IF jsonb_typeof(responder)<>'string' THEN RETURN false; END IF;
        address=(responder #>> '{}')::inet;
        IF family(address)<>family(target_address) OR host(address)<>(responder #>> '{}') OR address='0.0.0.0'::inet OR address='::'::inet
           OR address <<='224.0.0.0/4'::inet OR address <<='ff00::/8'::inet
           OR address <<='::ffff:0:0/96'::inet THEN RETURN false; END IF;
    END LOOP;
    IF EXISTS(SELECT 1 FROM jsonb_array_elements(document->'responders') r(value) GROUP BY value HAVING count(*)>1) THEN RETURN false; END IF;
    RETURN true;
EXCEPTION WHEN invalid_text_representation OR invalid_datetime_format OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END;
$$;

DO $$
DECLARE target regclass;
BEGIN
    FOR target IN
        SELECT c.oid::regclass FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relname='entity_evidence' AND c.relkind='r'
          AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        EXECUTE format('ALTER TABLE %s ADD COLUMN IF NOT EXISTS icmp_measurement jsonb',target);
        IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=target AND conname='entity_evidence_icmp_measurement_check') THEN
            EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_evidence_icmp_measurement_check CHECK
                (icmp_measurement IS NULL OR (source_kind=''path_agent'' AND alias_kind=''address''
                 AND source_ref=''icmp:configured-test'' AND configured_ref ~ ''^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$''
                 AND public.probectl_icmp_measurement_valid(icmp_measurement,alias_value::inet)
                 AND observed_at=(icmp_measurement->>''completed_at'')::timestamptz)) NOT VALID',target);
        END IF;
    END LOOP;
END $$;
