-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- lock-ok: a nullable column and NOT VALID constraint leave old observations
-- untouched and avoid scanning them under the metadata lock.
CREATE OR REPLACE FUNCTION public.probectl_snmp_physical_inventory_valid(document jsonb)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE PARALLEL SAFE SET search_path=pg_catalog AS $$
BEGIN
    IF jsonb_typeof(document) IS DISTINCT FROM 'object'
       OR jsonb_typeof(document->'version') IS DISTINCT FROM 'number'
       OR document->>'version' IS DISTINCT FROM '1'
       OR jsonb_typeof(document->'available') IS DISTINCT FROM 'boolean'
       OR octet_length(document::text) > 2097152
       OR document - ARRAY['version','available','components'] <> '{}'::jsonb THEN RETURN false; END IF;
    IF document->>'available'='false' THEN RETURN NOT document ? 'components'; END IF;
    IF jsonb_typeof(document->'components') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
    RETURN jsonb_array_length(document->'components') BETWEEN 1 AND 512;
END $$;

CREATE OR REPLACE FUNCTION public.probectl_install_snmp_physical_inventory(target_schema text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE target regclass; relation text;
BEGIN
    IF target_schema IS NULL OR target_schema !~ '^(public|t_[0-9a-f]{32})$' THEN
        RAISE EXCEPTION 'unsupported physical inventory schema' USING ERRCODE='23514';
    END IF;
    relation=format('%I.entity_evidence',target_schema);
    target=to_regclass(relation);
    IF target IS NULL THEN RAISE EXCEPTION 'evidence relation is missing' USING ERRCODE='23514'; END IF;
    EXECUTE format('ALTER TABLE %s ADD COLUMN IF NOT EXISTS snmp_physical_inventory jsonb',relation);
    IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=target AND conname='entity_evidence_snmp_physical_inventory_check') THEN
        EXECUTE format('ALTER TABLE %s ADD CONSTRAINT entity_evidence_snmp_physical_inventory_check CHECK
            ((source_ref=''snmp:physical-inventory'')=(snmp_physical_inventory IS NOT NULL) AND
             (snmp_physical_inventory IS NULL OR
              (source_kind=''device_target'' AND alias_kind=''address''
               AND public.probectl_snmp_physical_inventory_valid(snmp_physical_inventory)))) NOT VALID',relation);
    END IF;
END $$;

DO $$
DECLARE schema_name text;
BEGIN
    FOR schema_name IN SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relname='entity_evidence' AND c.relkind='r'
          AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        PERFORM public.probectl_install_snmp_physical_inventory(schema_name);
    END LOOP;
END $$;
