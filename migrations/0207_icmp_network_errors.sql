-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Optional collector facts reuse immutable tenant/source evidence and its
-- existing lifecycle. No new authority plane, table or retention subsystem.
-- lock-ok: nullable column and NOT VALID checks do not scan historical rows.
CREATE OR REPLACE FUNCTION public.probectl_icmp_measurement_base_valid(document jsonb, target_address inet)
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

-- Version 2 preserves challenge-matched network errors on the same immutable
-- evidence row. Existing pooled/silo constraints call this shared validator.
CREATE OR REPLACE FUNCTION public.probectl_icmp_measurement_valid(document jsonb, target_address inet)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE item jsonb; address inet; field_name text; requested bigint; received timestamptz;
BEGIN
    IF document IS NULL THEN RETURN true; END IF;
    IF document->'version'='1'::jsonb THEN
        RETURN public.probectl_icmp_measurement_base_valid(document,target_address);
    END IF;
    IF document->'version' IS DISTINCT FROM '2'::jsonb
       OR jsonb_typeof(document) IS DISTINCT FROM 'object'
       OR (SELECT count(*) FROM jsonb_object_keys(document))<>14
       OR NOT public.probectl_icmp_measurement_base_valid((document-'network_errors') || '{"version":1}'::jsonb,target_address)
       OR jsonb_typeof(document->'network_errors') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
    requested=(document->>'requested')::bigint;
    IF jsonb_array_length(document->'network_errors')=0
       OR jsonb_array_length(document->'network_errors')>(document->>'transmitted')::bigint
       OR EXISTS(SELECT 1 FROM jsonb_array_elements(document->'network_errors') r(value)
                 GROUP BY value->'sequence' HAVING count(*)>1) THEN RETURN false; END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(document->'network_errors') LOOP
        IF jsonb_typeof(item) IS DISTINCT FROM 'object'
           OR (SELECT count(*) FROM jsonb_object_keys(item))<>7 THEN RETURN false; END IF;
        FOREACH field_name IN ARRAY ARRAY['sequence','type','code'] LOOP
            IF jsonb_typeof(item->field_name) IS DISTINCT FROM 'number'
               OR (item->>field_name) !~ '^(0|[1-9][0-9]{0,9})$'
               OR (item->>field_name)::bigint>4294967295 THEN RETURN false; END IF;
        END LOOP;
        IF (item->>'sequence')::bigint>=requested OR (item->>'code')::bigint>255
           OR (family(target_address)=4 AND item->'type'<>'3'::jsonb)
           OR (family(target_address)=6 AND item->'type'<>'1'::jsonb)
           OR jsonb_typeof(item->'conflicting') IS DISTINCT FROM 'boolean'
           OR jsonb_typeof(item->'packet_digest') IS DISTINCT FROM 'string'
           OR (item->>'packet_digest') !~ '^[0-9a-f]{64}$'
           OR item->>'packet_digest'=repeat('0',64)
           OR jsonb_typeof(item->'responder') IS DISTINCT FROM 'string'
           OR jsonb_typeof(item->'received_at') IS DISTINCT FROM 'string'
           OR (item->>'received_at') !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?Z$' THEN RETURN false; END IF;
        address=(item->>'responder')::inet;
        received=(item->>'received_at')::timestamptz;
        IF family(address)<>family(target_address) OR host(address)<>item->>'responder'
           OR address='0.0.0.0'::inet OR address='::'::inet
           OR address <<='224.0.0.0/4'::inet OR address <<='ff00::/8'::inet OR address <<='::ffff:0:0/96'::inet
           OR received<(document->>'started_at')::timestamptz
           OR received>(document->>'completed_at')::timestamptz THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
EXCEPTION WHEN invalid_text_representation OR invalid_datetime_format OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END;
$$;
