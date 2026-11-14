-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Version3 uses the same immutable evidence rows, source authority and lifecycle.
-- Preserve the complete legacy validator; shared validators cover pooled/siloed
-- tables and future copies. No original body or index timestamp is rewritten.
CREATE OR REPLACE FUNCTION public.probectl_icmp_measurement_legacy_valid(document jsonb, target_address inet)
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

-- PostgreSQL timestamps have microsecond resolution. Parse the RFC3339 fraction
-- separately so completion/error ordering retains all original nanoseconds.
CREATE OR REPLACE FUNCTION public.probectl_icmp_clock_ns(value text)
RETURNS numeric LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE fraction text;
BEGIN
    IF value IS NULL OR value !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,9})?Z$' THEN RETURN NULL; END IF;
    fraction=substring(value FROM '\.([0-9]{1,9})Z$');
    RETURN extract(epoch FROM (substring(value FROM 1 FOR 19)||'Z')::timestamptz)*1000000000
           +COALESCE(rpad(fraction,9,'0')::numeric,0);
EXCEPTION WHEN invalid_text_representation OR invalid_datetime_format OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION public.probectl_icmp_measurement_valid(document jsonb, target_address inet)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE original jsonb; trips jsonb; sample jsonb; item jsonb; duration numeric;
    started numeric; completed numeric; received numeric;
BEGIN
    IF document IS NULL THEN RETURN true; END IF;
    IF document->'version' IS DISTINCT FROM '3'::jsonb THEN
        RETURN public.probectl_icmp_measurement_legacy_valid(document,target_address);
    END IF;
    IF jsonb_typeof(document) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
    original=document-'round_trips';
    IF original ? 'network_errors' THEN
        IF NOT COALESCE(public.probectl_icmp_measurement_legacy_valid(original||'{"version":2}'::jsonb,target_address),false) THEN RETURN false; END IF;
    ELSE
        IF NOT COALESCE(public.probectl_icmp_measurement_base_valid(original||'{"version":1}'::jsonb,target_address),false) THEN RETURN false; END IF;
    END IF;
    trips=document->'round_trips';
    IF jsonb_typeof(trips) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(trips))<>2
       OR jsonb_typeof(trips->'nanos') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
    IF jsonb_array_length(trips->'nanos')<>(document->>'replies')::bigint
       OR jsonb_typeof(trips->'execution_nanos') IS DISTINCT FROM 'number'
       OR (trips->>'execution_nanos') !~ '^(0|[1-9][0-9]{0,18})$' THEN RETURN false; END IF;
    duration=(trips->>'execution_nanos')::numeric;
    IF duration>9223372036854775807 THEN RETURN false; END IF;
    FOR sample IN SELECT value FROM jsonb_array_elements(trips->'nanos') LOOP
        IF jsonb_typeof(sample) IS DISTINCT FROM 'number' OR (sample #>> '{}') !~ '^(0|[1-9][0-9]{0,18})$'
           OR (sample #>> '{}')::numeric>duration THEN RETURN false; END IF;
    END LOOP;
    started=public.probectl_icmp_clock_ns(document->>'started_at');
    completed=public.probectl_icmp_clock_ns(document->>'completed_at');
    IF started IS NULL OR completed IS NULL OR completed<started THEN RETURN false; END IF;
    FOR item IN SELECT value FROM jsonb_array_elements(COALESCE(document->'network_errors','[]'::jsonb)) LOOP
        received=public.probectl_icmp_clock_ns(item->>'received_at');
        IF received IS NULL OR received<started OR received>completed THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
EXCEPTION WHEN invalid_text_representation OR invalid_datetime_format OR datetime_field_overflow OR numeric_value_out_of_range THEN RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION public.probectl_icmp_measurement_index_at(document jsonb)
RETURNS timestamptz LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
BEGIN
    IF document->'version'='3'::jsonb THEN
        -- Trim BEFORE the cast: casting a nine-digit fraction rounds it and
        -- can move a valid original into the next indexed microsecond.
        RETURN regexp_replace(document->>'completed_at','(\.[0-9]{6})[0-9]{1,3}Z$','\1Z')::timestamptz;
    END IF;
    RETURN (document->>'completed_at')::timestamptz;
EXCEPTION WHEN invalid_text_representation OR invalid_datetime_format OR datetime_field_overflow THEN RETURN NULL;
END;
$$;

-- lock-ok: nullable-column/check catch-up is metadata-only, with no historical scan.
CREATE OR REPLACE FUNCTION public.probectl_install_icmp_measurement(schema_name text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE target regclass; definition text;
BEGIN
    IF schema_name IS NULL OR (schema_name<>'public' AND schema_name !~ '^t_[0-9a-f]{32}$') THEN
        RAISE EXCEPTION 'invalid managed ICMP schema';
    END IF;
    target=to_regclass(format('%I.entity_evidence',schema_name));
    IF target IS NULL THEN RETURN; END IF;
    EXECUTE format('ALTER TABLE %s ADD COLUMN IF NOT EXISTS icmp_measurement jsonb',target);
    SELECT pg_get_constraintdef(oid) INTO definition FROM pg_constraint
    WHERE conrelid=target AND conname='entity_evidence_icmp_measurement_check';
    IF definition IS NOT NULL AND position('probectl_icmp_measurement_index_at' IN definition)=0 THEN
        EXECUTE format('ALTER TABLE %s DROP CONSTRAINT entity_evidence_icmp_measurement_check',target);
        definition=NULL;
    END IF;
    IF definition IS NULL THEN
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_evidence_icmp_measurement_check CHECK
            (icmp_measurement IS NULL OR (source_kind=''path_agent'' AND alias_kind=''address''
             AND source_ref=''icmp:configured-test'' AND configured_ref ~ ''^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$''
             AND public.probectl_icmp_measurement_valid(icmp_measurement,alias_value::inet)
             AND observed_at=public.probectl_icmp_measurement_index_at(icmp_measurement))) NOT VALID',target);
    END IF;
END;
$$;
DO $$
DECLARE managed text;
BEGIN
    FOR managed IN SELECT nspname FROM pg_namespace
        WHERE nspname='public' OR nspname ~ '^t_[0-9a-f]{32}$'
    LOOP
        PERFORM public.probectl_install_icmp_measurement(managed);
    END LOOP;
END $$;
