-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- The existing pooled and siloed CHECK constraints keep these function names.
-- This adds one typed body without altering tenant keys, rows or indexes.
CREATE OR REPLACE FUNCTION public.probectl_icmp_egress_valid(document jsonb, target_address inet)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE witness jsonb; source_address inet; address inet;
BEGIN
    witness=document->'egress';
    IF jsonb_typeof(witness) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
    IF (SELECT count(*) FROM jsonb_object_keys(witness))<>4
       OR jsonb_typeof(witness->'interface') IS DISTINCT FROM 'string'
       OR (witness->>'interface') !~ '^[a-zA-Z0-9_.-]{1,15}$'
       OR witness->>'interface' IN ('.','..')
       OR jsonb_typeof(witness->'peer_mac') IS DISTINCT FROM 'string'
       OR (witness->>'peer_mac') !~ '^[0-9a-f][02468ace](:[0-9a-f]{2}){5}$'
       OR witness->>'peer_mac'='00:00:00:00:00:00'
       OR jsonb_typeof(witness->'source') IS DISTINCT FROM 'string'
       OR jsonb_typeof(witness->'transmitted') IS DISTINCT FROM 'number'
       OR (witness->>'transmitted') !~ '^([1-9]|[12][0-9]|3[0-2])$'
       OR witness->'transmitted' IS DISTINCT FROM document->'transmitted'
       OR witness->'transmitted' IS DISTINCT FROM document->'requested'
       OR document->'read_complete' IS DISTINCT FROM 'true'::jsonb
       OR document->'canceled' IS DISTINCT FROM 'false'::jsonb
       OR document->'io_failed' IS DISTINCT FROM 'false'::jsonb THEN RETURN false; END IF;
    source_address=(witness->>'source')::inet;
    IF target_address IS NULL OR family(source_address)<>family(target_address)
       OR host(source_address)<>witness->>'source' OR source_address=target_address THEN RETURN false; END IF;
    FOREACH address IN ARRAY ARRAY[source_address,target_address] LOOP
        IF address IN ('0.0.0.0'::inet,'255.255.255.255'::inet,'::'::inet,'::1'::inet)
           OR address <<='127.0.0.0/8'::inet OR address <<='169.254.0.0/16'::inet
           OR address <<='224.0.0.0/4'::inet OR address <<='fe80::/10'::inet
           OR address <<='ff00::/8'::inet OR address <<='::ffff:0:0/96'::inet THEN RETURN false; END IF;
    END LOOP;
    RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN RETURN false;
END;
$$;

CREATE OR REPLACE FUNCTION public.probectl_icmp_measurement_valid(document jsonb, target_address inet)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE original jsonb; trips jsonb; sample jsonb; item jsonb; duration numeric;
    started numeric; completed numeric; received numeric;
BEGIN
    IF document IS NULL THEN RETURN true; END IF;
    IF document->'version' IS DISTINCT FROM '3'::jsonb AND document->'version' IS DISTINCT FROM '4'::jsonb THEN
        RETURN public.probectl_icmp_measurement_legacy_valid(document,target_address);
    END IF;
    IF jsonb_typeof(document) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
    original=document-'round_trips';
    IF document->'version'='4'::jsonb THEN
        IF NOT public.probectl_icmp_egress_valid(document,target_address) THEN RETURN false; END IF;
        original=original-'egress';
    END IF;
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
    IF document->'version' IN ('3'::jsonb,'4'::jsonb) THEN
        -- Trim BEFORE the cast: casting a nine-digit fraction rounds it and
        -- can move a valid original into the next indexed microsecond.
        RETURN regexp_replace(document->>'completed_at','(\.[0-9]{6})[0-9]{1,3}Z$','\1Z')::timestamptz;
    END IF;
    RETURN (document->>'completed_at')::timestamptz;
EXCEPTION WHEN invalid_text_representation OR invalid_datetime_format OR datetime_field_overflow THEN RETURN NULL;
END;
$$;
