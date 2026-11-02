-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Expand only tag values. NOT VALID enforces new writes immediately without
-- scanning under the DDL lock. Every old 128-byte value already satisfies the
-- wider character/byte limits, so existing data needs no rewrite or scan.
-- lock-ok: replace metadata-only tag CHECKs; no table scan or row rewrite.
-- Existing tag metadata, ownership FKs, RLS and revision triggers stay intact.
ALTER TABLE tenant_tag_assignments
    DROP CONSTRAINT IF EXISTS tenant_tag_assignments_value_check;
ALTER TABLE tenant_tag_rules
    DROP CONSTRAINT IF EXISTS tenant_tag_rules_value_check;

DO $tag_value_limit$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='tenant_tag_assignments'::regclass
                     AND conname='tenant_tag_assignments_value_v2_check') THEN
        ALTER TABLE tenant_tag_assignments
            ADD CONSTRAINT tenant_tag_assignments_value_v2_check
            CHECK (char_length(value) BETWEEN 1 AND 24000
                   AND octet_length(value) <= 96000
                   AND value !~ '[[:cntrl:]]') NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='tenant_tag_rules'::regclass
                     AND conname='tenant_tag_rules_value_v2_check') THEN
        ALTER TABLE tenant_tag_rules
            ADD CONSTRAINT tenant_tag_rules_value_v2_check
            CHECK (char_length(value) BETWEEN 1 AND 24000
                   AND octet_length(value) <= 96000
                   AND value !~ '[[:cntrl:]]') NOT VALID;
    END IF;
END;
$tag_value_limit$;
