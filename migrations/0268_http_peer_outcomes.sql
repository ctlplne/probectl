-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Older readers retain the original probe_outcome document and older writers
-- omit this nullable column. No existing evidence is rewritten or backfilled.
-- lock-ok: nullable column and NOT VALID check avoid scanning evidence.
CREATE OR REPLACE FUNCTION public.probectl_install_probe_https_peer(target_schema text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE target regclass; relation text;
BEGIN
    IF target_schema IS NULL OR target_schema !~ '^(public|t_[0-9a-f]{32})$' THEN
        RAISE EXCEPTION 'unsupported HTTPS peer evidence schema' USING ERRCODE='23514';
    END IF;
    relation=format('%I.entity_evidence',target_schema);
    target=to_regclass(relation);
    IF target IS NULL THEN RAISE EXCEPTION 'evidence relation is missing' USING ERRCODE='23514'; END IF;
    EXECUTE format('ALTER TABLE %s ADD COLUMN IF NOT EXISTS probe_https_peer inet',relation);
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=target AND conname='entity_evidence_probe_https_peer_check') THEN
        EXECUTE format($check$ALTER TABLE %s ADD CONSTRAINT entity_evidence_probe_https_peer_check CHECK (
            probe_https_peer IS NULL OR (
                probe_outcome->'version' IS NOT DISTINCT FROM '2'::jsonb
                AND probe_outcome->'canceled' IS NOT DISTINCT FROM 'false'::jsonb
                AND probe_outcome->'http_response'->'tls_verified' IS NOT DISTINCT FROM 'true'::jsonb
                AND probe_outcome->'http_response'->'same_origin' IS NOT DISTINCT FROM 'true'::jsonb
                AND masklen(probe_https_peer) = CASE family(probe_https_peer) WHEN 4 THEN 32 ELSE 128 END
                AND NOT (probe_https_peer <<= ANY (ARRAY[
                    '0.0.0.0/32'::inet, '10.0.0.0/8'::inet, '127.0.0.0/8'::inet,
                    '169.254.0.0/16'::inet, '172.16.0.0/12'::inet, '192.168.0.0/16'::inet,
                    '224.0.0.0/4'::inet, '255.255.255.255/32'::inet,
                    '::/128'::inet, '::1/128'::inet, '::ffff:0:0/96'::inet,
                    'fc00::/7'::inet, 'fe80::/10'::inet, 'ff00::/8'::inet
                ]))
            )
        ) NOT VALID$check$,relation);
    END IF;
END $$;

DO $$
DECLARE schema_name text;
BEGIN
    FOR schema_name IN SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relname='entity_evidence' AND c.relkind='r'
          AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        PERFORM public.probectl_install_probe_https_peer(schema_name);
    END LOOP;
END $$;
