-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- lock-ok: nullable columns with no defaults. Existing raw rows retain
-- their original retention and remain readable before pattern coverage.
SET LOCAL lock_timeout='5s';
DO $device_syslog_patterns$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT n.nspname AS schema_name
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
         WHERE c.relname='device_syslog' AND c.relkind IN ('r','p')
           AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        EXECUTE format('ALTER TABLE %I.device_syslog
            ADD COLUMN IF NOT EXISTS pattern_version integer,
            ADD COLUMN IF NOT EXISTS pattern_id text,
            ADD COLUMN IF NOT EXISTS pattern_kind text', target.schema_name);
    END LOOP;
END;
$device_syslog_patterns$;
