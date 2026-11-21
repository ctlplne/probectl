-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Keep the pending fault queue within the tenant erasure write barrier.
-- Repair existing pooled and physical silo tables. New silo tables get the
-- same lifecycle trigger through the ordinary silo planner.
-- lock-ok: trigger metadata only, without scanning or rewriting retained rows.
DO $syslog_fault_write_fence$
DECLARE target record;
BEGIN
    FOR target IN
        SELECT n.nspname AS schema_name
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
         WHERE c.relname = 'device_syslog_fault_queue' AND c.relkind IN ('r', 'p')
           AND (n.nspname = 'public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS tenant_write_fence ON %I.device_syslog_fault_queue', target.schema_name);
        EXECUTE format('CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON %I.device_syslog_fault_queue
            FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()', target.schema_name);
        EXECUTE format('ALTER TABLE %I.device_syslog_fault_queue ENABLE ALWAYS TRIGGER tenant_write_fence', target.schema_name);
    END LOOP;
END
$syslog_fault_write_fence$;
