-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Extend the existing FORCE-RLS import domain with reviewed exported prefixes.
-- NOT VALID checks cover new writes immediately without scanning old plans.
-- lock-ok: replaces an existing check with an additive superset in one
-- transaction. The new NOT VALID check avoids an existing row scan.
ALTER TABLE nms_import_sources
    DROP CONSTRAINT IF EXISTS nms_import_sources_source_kind_check;
ALTER TABLE nms_import_sources
    ADD CONSTRAINT nms_import_sources_source_kind_check
    CHECK (source_kind IN ('librenms', 'zabbix', 'orion', 'prtg', 'sightline', 'defenseflow')) NOT VALID;

-- lock-ok: replaces an existing check with an additive superset in one
-- transaction. The new NOT VALID check avoids an existing row scan.
ALTER TABLE nms_import_pages
    DROP CONSTRAINT IF EXISTS nms_import_pages_resource_kind_check;
ALTER TABLE nms_import_pages
    ADD CONSTRAINT nms_import_pages_resource_kind_check
    CHECK (resource_kind IN ('devices', 'locations', 'nodes', 'groups', 'memberships',
                            'member_removals', 'rules', 'hosts', 'probes', 'managed_objects', 'protected_objects')) NOT VALID;

-- lock-ok: replaces an existing check with an additive superset in one
-- transaction. The new NOT VALID check avoids an existing row scan.
ALTER TABLE nms_import_rows
    DROP CONSTRAINT IF EXISTS nms_import_rows_object_kind_check;
ALTER TABLE nms_import_rows
    ADD CONSTRAINT nms_import_rows_object_kind_check
    CHECK (object_kind IN ('device', 'site', 'group', 'membership', 'poll_setting', 'alert_rule', 'prefix')) NOT VALID;
ALTER TABLE nms_import_rows
    ADD COLUMN IF NOT EXISTS source_mapping_sha256 text;
DO $protected_prefix_mapping$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='nms_import_rows'::regclass
                   AND conname='nms_import_rows_source_mapping_sha256_check') THEN
        ALTER TABLE nms_import_rows ADD CONSTRAINT nms_import_rows_source_mapping_sha256_check
        CHECK ((object_kind='prefix')=(source_mapping_sha256 IS NOT NULL)
               AND (source_mapping_sha256 IS NULL OR source_mapping_sha256 ~ '^[0-9a-f]{64}$')) NOT VALID;
    END IF;
END $protected_prefix_mapping$;

-- lock-ok: replaces an existing check with an additive superset in one
-- transaction. The new NOT VALID check avoids an existing row scan.
ALTER TABLE nms_import_provenance
    DROP CONSTRAINT IF EXISTS nms_import_provenance_object_kind_check;
ALTER TABLE nms_import_provenance
    ADD CONSTRAINT nms_import_provenance_object_kind_check
    CHECK (object_kind IN ('device','site','prefix')) NOT VALID;
