-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Complete optional metadata on the existing sender-bound evidence row.
-- lock-ok: nullable column and NOT VALID checks do not scan historical rows.
-- The 8 MiB storage bound exceeds the closed JSON grammar expansion of the
-- existing complete 1 MiB evidence request. No prefix count is truncated.
CREATE OR REPLACE FUNCTION public.probectl_snmp_prefix_snapshot_valid(document jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
DECLARE prefix_row jsonb; prefix_text text; address inet;
BEGIN
    IF document IS NULL THEN RETURN true; END IF;
    IF jsonb_typeof(document)<>'array' OR octet_length(document::text)>8388608 THEN RETURN false; END IF;
    IF jsonb_array_length(document)=0 THEN RETURN false; END IF;
    FOR prefix_row IN SELECT value FROM jsonb_array_elements(document) LOOP
        IF jsonb_typeof(prefix_row)<>'object' THEN RETURN false; END IF;
        IF (SELECT count(*) FROM jsonb_object_keys(prefix_row))<>3
            OR jsonb_typeof(prefix_row->'if_index') IS DISTINCT FROM 'number'
            OR jsonb_typeof(prefix_row->'prefix') IS DISTINCT FROM 'string'
            OR jsonb_typeof(prefix_row->'on_link') IS DISTINCT FROM 'boolean'
            OR (prefix_row->>'if_index')!~'^[1-9][0-9]{0,9}$'
            OR (prefix_row->>'if_index')::bigint>2147483647 THEN RETURN false; END IF;
        prefix_text := prefix_row->>'prefix';
        IF length(prefix_text)>43 OR position('/' IN prefix_text)=0 THEN RETURN false; END IF;
        address := prefix_text::inet;
        IF network(address)::text<>prefix_text OR address <<='::ffff:0:0/96'::inet THEN RETURN false; END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM jsonb_array_elements(document) AS p(value)
        GROUP BY value->>'if_index',value->>'prefix' HAVING count(*)>1) THEN RETURN false; END IF;
    RETURN true;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN false;
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
        EXECUTE format('ALTER TABLE %s ADD COLUMN IF NOT EXISTS snmp_interface_prefixes jsonb',target);
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=target AND conname='entity_evidence_snmp_prefix_snapshot_check') THEN
            EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_evidence_snmp_prefix_snapshot_check CHECK
                (snmp_interface_prefixes IS NULL OR
                 (source_kind=''device_target'' AND alias_kind=''address''
                  AND source_ref=''snmp:configured-target''
                  AND public.probectl_snmp_prefix_snapshot_valid(snmp_interface_prefixes))) NOT VALID',target);
        END IF;
    END LOOP;
END $$;
