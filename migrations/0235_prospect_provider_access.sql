-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Store provider consent on the existing tenant-owned engagement. Its
-- separate revision preserves the lifetime and scheduled-erasure consent.
-- lock-ok: additive columns with a constant default and a NOT VALID check.
DO $prospect_provider_access$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT n.nspname AS schema_name, c.oid AS table_oid
          FROM pg_catalog.pg_class AS c
          JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
         WHERE c.relname='prospect_engagements'
           AND c.relkind IN ('r','p')
           AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        EXECUTE format('ALTER TABLE %I.prospect_engagements
            ADD COLUMN IF NOT EXISTS provider_access_revision bigint NOT NULL DEFAULT 0,
            ADD COLUMN IF NOT EXISTS provider_engagement_revision bigint,
            ADD COLUMN IF NOT EXISTS provider_request_id uuid', target.schema_name);
        IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint
            WHERE conrelid=target.table_oid AND conname='prospect_provider_access_v1') THEN
            EXECUTE format('ALTER TABLE %I.prospect_engagements ADD CONSTRAINT prospect_provider_access_v1 CHECK (
                provider_access_revision >= 0
                AND (provider_engagement_revision IS NULL OR provider_engagement_revision <= revision)
                AND (provider_engagement_revision IS NOT NULL OR provider_request_id IS NULL)
            ) NOT VALID', target.schema_name);
        END IF;
    END LOOP;
END;
$prospect_provider_access$;
