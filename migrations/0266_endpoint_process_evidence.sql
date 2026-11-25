-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Keep process evidence on the existing RLS-scoped agent row, including
-- already provisioned silos. Legacy agents have no endpoint evidence.
-- lock-ok: additive nullable column with no default. The inline check admits NULL.
SET LOCAL lock_timeout = '5s';
DO $endpoint_process$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT n.nspname AS schema_name
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE c.relname = 'agents' AND c.relkind IN ('r', 'p')
           AND (n.nspname = 'public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        EXECUTE format('ALTER TABLE %I.agents ADD COLUMN IF NOT EXISTS endpoint_process jsonb
            CONSTRAINT agents_endpoint_process_shape CHECK (
                endpoint_process IS NULL OR (
                    jsonb_typeof(endpoint_process) = ''object'' AND octet_length(endpoint_process::text) <= 512
                )
            )', target.schema_name);
    END LOOP;
END;
$endpoint_process$;
