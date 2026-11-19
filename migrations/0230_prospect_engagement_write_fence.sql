-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Reuse the existing full-erasure barrier in the pooled template and every
-- already provisioned copy of the tenant-owned table.
-- lock-ok: trigger metadata only; existing engagements need no row rewrite.
DO $prospect_engagement_write_fence$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT n.nspname AS schema_name
          FROM pg_catalog.pg_class AS c
          JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
         WHERE c.relname='prospect_engagements'
           AND c.relkind IN ('r','p')
           AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS tenant_write_fence ON %I.prospect_engagements', target.schema_name);
        EXECUTE format('CREATE TRIGGER tenant_write_fence BEFORE INSERT OR UPDATE ON %I.prospect_engagements FOR EACH ROW EXECUTE FUNCTION public.probectl_enforce_tenant_write_fence()', target.schema_name);
        EXECUTE format('ALTER TABLE %I.prospect_engagements ENABLE ALWAYS TRIGGER tenant_write_fence', target.schema_name);
    END LOOP;
END
$prospect_engagement_write_fence$;
