-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Reuse sender-bound entity evidence and its existing tenant retention.
-- lock-ok: a nullable column and NOT VALID constraint avoid rewriting or
-- scanning retained observations under the DDL lock. Legacy rows stay absent.
CREATE OR REPLACE FUNCTION public.probectl_bmp_peer_session_valid(document jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE field_name text; reason integer; notified boolean;
BEGIN
 IF document IS NULL THEN RETURN true; END IF;
 IF jsonb_typeof(document)<>'object' OR document->>'version' IS DISTINCT FROM '1'
 OR jsonb_typeof(document->'version') IS DISTINCT FROM 'number'
 OR document->>'state' NOT IN ('up','down','monitoring_withdrawn')
 OR jsonb_typeof(document->'state') IS DISTINCT FROM 'string'
 OR jsonb_typeof(document->'peer_address') IS DISTINCT FROM 'string'
 OR jsonb_typeof(document->'peer_asn') IS DISTINCT FROM 'number'
 OR (document->>'peer_asn') !~ '^[1-9][0-9]{0,9}$'
 OR (document->>'peer_asn')::numeric>4294967295
 OR jsonb_typeof(document->'flags') IS DISTINCT FROM 'number'
 OR (document->>'flags') !~ '^[0-9]{1,3}$'
 OR (document->>'flags')::integer NOT IN (0,16,32,48,64,80,96,112,128,144,160,176,192,208,224,240)
 OR jsonb_typeof(document->'frame_digest') IS DISTINCT FROM 'string'
 OR (document->>'frame_digest') !~ '^[0-9a-f]{64}$'
 OR jsonb_typeof(document->'raw_frame') IS DISTINCT FROM 'string'
 OR octet_length(decode(document->>'raw_frame','base64'))<48 THEN RETURN false; END IF;
 IF host((document->>'peer_address')::inet) IS DISTINCT FROM document->>'peer_address'
 OR (document->>'peer_address')::inet <<= '224.0.0.0/4'::inet
 OR (document->>'peer_address')::inet <<= 'ff00::/8'::inet
 OR (document->>'peer_address') IN ('0.0.0.0','::') THEN RETURN false; END IF;
 FOR field_name IN SELECT jsonb_object_keys(document) LOOP
  IF field_name NOT IN ('version','state','peer_address','peer_asn','flags','raw_frame','frame_digest','down_reason','fsm_event','notification_code','notification_subcode') THEN RETURN false; END IF;
 END LOOP;
 IF document->>'state'='up' THEN
  RETURN NOT(document ?| ARRAY['down_reason','fsm_event','notification_code','notification_subcode']);
 END IF;
 IF jsonb_typeof(document->'down_reason') IS DISTINCT FROM 'number' OR (document->>'down_reason') !~ '^[1-6]$' THEN RETURN false; END IF;
 reason=(document->>'down_reason')::integer;
 IF (document->>'state'='monitoring_withdrawn') IS DISTINCT FROM (reason=5) THEN RETURN false; END IF;
 notified=reason IN (1,3);
 IF notified IS DISTINCT FROM (document ? 'notification_code') OR notified IS DISTINCT FROM (document ? 'notification_subcode') THEN RETURN false; END IF;
 FOREACH field_name IN ARRAY ARRAY['notification_code','notification_subcode','fsm_event'] LOOP
  IF document ? field_name THEN
   IF jsonb_typeof(document->field_name) IS DISTINCT FROM 'number' OR (document->>field_name) !~ '^[0-9]{1,5}$' THEN RETURN false; END IF;
   IF field_name='fsm_event' THEN
    IF reason<>2 OR (document->>field_name)::integer NOT BETWEEN 1 AND 65535 THEN RETURN false; END IF;
   ELSIF (document->>field_name)::integer>255 THEN RETURN false; END IF;
  END IF;
 END LOOP;
 RETURN true;
EXCEPTION WHEN invalid_text_representation OR invalid_parameter_value OR numeric_value_out_of_range THEN RETURN false;
END $$;

CREATE OR REPLACE FUNCTION public.probectl_install_bmp_peer_session(target_schema text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE target regclass; relation text;
BEGIN
    IF target_schema IS NULL OR target_schema !~ '^(public|t_[0-9a-f]{32})$' THEN
        RAISE EXCEPTION 'unsupported BMP session schema' USING ERRCODE='23514';
    END IF;
    relation=format('%I.entity_evidence',target_schema);
    target=to_regclass(relation);
    IF target IS NULL THEN RAISE EXCEPTION 'evidence relation is missing' USING ERRCODE='23514'; END IF;
    EXECUTE format('ALTER TABLE %s ADD COLUMN IF NOT EXISTS bmp_peer_session jsonb DEFAULT NULL',relation);
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=target AND conname='entity_evidence_bmp_peer_session_check') THEN
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_evidence_bmp_peer_session_check CHECK
            (bmp_peer_session IS NULL OR
             (source_kind=''bmp_peer'' AND alias_kind=''bmp_peer_id''
              AND alias_value=(bmp_peer_session->>''peer_address'')||''/as''||(bmp_peer_session->>''peer_asn'')
              AND source_ref=''bmp:router:''||configured_ref||'':peer-asn:''||(bmp_peer_session->>''peer_asn'')
              AND origin_serial IS NOT NULL
              AND public.probectl_bmp_peer_session_valid(bmp_peer_session))) NOT VALID',relation);
    END IF;
END $$;

DO $$
DECLARE schema_name text;
BEGIN
    FOR schema_name IN SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relname='entity_evidence' AND c.relkind='r'
          AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        PERFORM public.probectl_install_bmp_peer_session(schema_name);
    END LOOP;
END $$;
