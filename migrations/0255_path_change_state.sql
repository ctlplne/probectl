-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- lock-ok: nullable metadata on the existing FORCE-RLS tests relation, with
-- no rewrite. The state stores only server-created round IDs and clocks.
CREATE OR REPLACE FUNCTION public.probectl_install_path_change_state(target_schema text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE relation text;
BEGIN
    IF target_schema IS NULL OR target_schema !~ '^(public|t_[0-9a-f]{32})$' THEN
        RAISE EXCEPTION 'unsupported path change schema' USING ERRCODE='23514';
    END IF;
    relation=format('%I.tests',target_schema);
    IF to_regclass(relation) IS NULL THEN RAISE EXCEPTION 'tests relation is missing' USING ERRCODE='23514'; END IF;
    EXECUTE format('ALTER TABLE %s ADD COLUMN IF NOT EXISTS path_change_state jsonb',relation);
END $$;

DO $$
DECLARE schema_name text;
BEGIN
    FOR schema_name IN SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE c.relname='tests' AND c.relkind='r'
          AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        PERFORM public.probectl_install_path_change_state(schema_name);
    END LOOP;
END $$;
