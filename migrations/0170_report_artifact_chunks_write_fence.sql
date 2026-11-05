-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Chunk writers participate in the same tenant erasure barrier as their
-- report parents. Repair both the pooled template and already provisioned
-- physical silos; future provision/catch-up uses the ordinary table recipe.
-- lock-ok: trigger metadata only; no historical body scan or rewrite.
DO $report_chunk_write_fence$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT n.nspname AS schema_name, c.relname AS table_name
          FROM pg_catalog.pg_class AS c
          JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
         WHERE c.relname='dashboard_report_artifact_chunks'
           AND c.relkind IN ('r','p')
           AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS tenant_write_fence ON %I.%I',
            target.schema_name, target.table_name);
        EXECUTE format('CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON %I.%I FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()',
            target.schema_name, target.table_name);
        EXECUTE format('ALTER TABLE %I.%I ENABLE ALWAYS TRIGGER tenant_write_fence',
            target.schema_name, target.table_name);
    END LOOP;
END
$report_chunk_write_fence$;
