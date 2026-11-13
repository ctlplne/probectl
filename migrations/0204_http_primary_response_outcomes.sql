-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Version 2 adds only primary HTTP response facts on the existing authenticated
-- outcome family. Version 1 remains byte-compatible and accepts no new member.
-- lock-ok: validator metadata only; no retained body scan or rewrite.
CREATE OR REPLACE FUNCTION public.probectl_probe_outcome_valid(document jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE field_name text;
BEGIN
    IF document IS NULL THEN RETURN true; END IF;
    IF jsonb_typeof(document)<>'object' THEN RETURN false; END IF;
    IF document->'version'='1'::jsonb THEN
        IF (SELECT count(*) FROM jsonb_object_keys(document))<>7 THEN RETURN false; END IF;
    ELSIF document->'version'='2'::jsonb THEN
        IF (SELECT count(*) FROM jsonb_object_keys(document))<>8
           OR document->>'canary_type' IS DISTINCT FROM 'http'
           OR jsonb_typeof(document->'http_response') IS DISTINCT FROM 'object' THEN RETURN false; END IF;
        IF (SELECT count(*) FROM jsonb_object_keys(document->'http_response'))<>3
           OR jsonb_typeof(document->'http_response'->'status_code') IS DISTINCT FROM 'number'
           OR (document->'http_response'->>'status_code') !~ '^[1-9][0-9]{2}$'
           OR jsonb_typeof(document->'http_response'->'tls_verified') IS DISTINCT FROM 'boolean'
           OR jsonb_typeof(document->'http_response'->'same_origin') IS DISTINCT FROM 'boolean' THEN RETURN false; END IF;
    ELSE
        RETURN false;
    END IF;
    IF jsonb_typeof(document->'definition_hash') IS DISTINCT FROM 'string'
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
