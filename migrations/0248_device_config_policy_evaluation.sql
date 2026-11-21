-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Store only decision metadata and line numbers on the row whose redacted
-- content they describe. Legacy archives retain an empty decision field.
-- lock-ok: nullable column with no default. The inline check admits NULL.
SET LOCAL lock_timeout='5s';
DO $device_policy_result$
DECLARE
    target record;
BEGIN
    FOR target IN
        SELECT n.nspname AS schema_name
          FROM pg_catalog.pg_class c
          JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
         WHERE c.relname='device_configs' AND c.relkind IN ('r','p')
           AND (n.nspname='public' OR n.nspname ~ '^t_[0-9a-f]{32}$')
    LOOP
        EXECUTE format('ALTER TABLE %I.device_configs ADD COLUMN IF NOT EXISTS config_policy_evaluation jsonb
            CONSTRAINT device_configs_policy_evaluation_shape
            CHECK (config_policy_evaluation IS NULL OR (
                entity_context_id IS NOT NULL AND
                jsonb_typeof(config_policy_evaluation)=''object'' AND
                octet_length(config_policy_evaluation::text)<=262144
            ))', target.schema_name);
    END LOOP;
END;
$device_policy_result$;
