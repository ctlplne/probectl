-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Reuse sender-bound entity evidence and its existing tenant retention.
-- lock-ok: a nullable column and NOT VALID constraint avoid rewriting or
-- scanning retained observations under the DDL lock. Legacy rows stay absent.
CREATE OR REPLACE FUNCTION public.probectl_snmp_interface_state_valid(document jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE field_name text;
BEGIN
    IF document IS NULL THEN RETURN true; END IF;
    IF jsonb_typeof(document)<>'object'
       OR jsonb_typeof(document->'version') IS DISTINCT FROM 'number'
       OR document->>'version' IS DISTINCT FROM '1'
       OR NOT (document ? 'oper_status' OR document ? 'admin_status') THEN RETURN false; END IF;
    FOR field_name IN SELECT jsonb_object_keys(document) LOOP
        IF field_name NOT IN ('version','oper_status','admin_status') THEN RETURN false; END IF;
    END LOOP;
    IF document ? 'oper_status' AND
       (jsonb_typeof(document->'oper_status') IS DISTINCT FROM 'number'
        OR (document->>'oper_status') !~ '^[1-7]$') THEN RETURN false; END IF;
    IF document ? 'admin_status' AND
       (jsonb_typeof(document->'admin_status') IS DISTINCT FROM 'number'
        OR (document->>'admin_status') !~ '^[1-3]$') THEN RETURN false; END IF;
    RETURN true;
END $$;

CREATE OR REPLACE FUNCTION public.probectl_install_snmp_interface_state(target_schema text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE target regclass; relation text;
BEGIN
    IF target_schema IS NULL OR target_schema !~ '^(public|t_[0-9a-f]{32})$' THEN
        RAISE EXCEPTION 'unsupported interface state schema' USING ERRCODE='23514';
    END IF;
    relation=format('%I.entity_evidence',target_schema);
    target=to_regclass(relation);
    IF target IS NULL THEN RAISE EXCEPTION 'evidence relation is missing' USING ERRCODE='23514'; END IF;
    EXECUTE format('ALTER TABLE %s ADD COLUMN IF NOT EXISTS snmp_interface_state jsonb DEFAULT NULL',relation);
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=target AND conname='entity_evidence_snmp_interface_state_check') THEN
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_evidence_snmp_interface_state_check CHECK
            (snmp_interface_state IS NULL OR
             (source_kind=''device_target'' AND alias_kind=''snmp_interface_id''
              AND source_ref=''snmp:ifIndex:''||alias_value
              AND public.probectl_snmp_interface_state_valid(snmp_interface_state))) NOT VALID',relation);
    END IF;
END $$;

DO $$
DECLARE schema_name text;
BEGIN
    FOR schema_name IN SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relname='entity_evidence' AND c.relkind='r'
          AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        PERFORM public.probectl_install_snmp_interface_state(schema_name);
    END LOOP;
END $$;
