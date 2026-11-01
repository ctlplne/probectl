-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-2b: live import is explicitly configured per tenant and routing context.
-- A source row stores no token value, only a reference to an operator-approved
-- tenant namespace. Existing sources and plans remain file/export-only.

-- lock-ok: import sources and plans are new, low-volume operator tables. These
-- nullable or constant-default columns are metadata-only additions.
ALTER TABLE nms_import_sources
    ADD COLUMN IF NOT EXISTS https_origin text,
    ADD COLUMN IF NOT EXISTS credential_ref text,
    ADD COLUMN IF NOT EXISTS fetch_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS config_version bigint NOT NULL DEFAULT 0;
ALTER TABLE nms_import_plans
    ADD COLUMN IF NOT EXISTS source_config_version bigint NOT NULL DEFAULT 0;

-- A populated endpoint belongs only to a LibreNMS source. The service checks
-- URL and tenant-specific reference policy before writing; these constraints
-- also prevent a direct database writer from persisting a plaintext or env:
-- credential as an apparent fetch configuration. NOT VALID avoids a table
-- scan while checking all new writes and updates.
DO $nms_source_shape$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'nms_import_sources_fetch_shape_check'
                     AND conrelid = 'nms_import_sources'::regclass) THEN
        -- lock-ok: additive check on the small import-source table.
        ALTER TABLE nms_import_sources
            ADD CONSTRAINT nms_import_sources_fetch_shape_check CHECK (
                config_version >= 0 AND (
                    (https_origin IS NULL AND credential_ref IS NULL AND NOT fetch_enabled)
                    OR (
                        source_kind = 'librenms' AND https_origin IS NOT NULL
                        AND credential_ref IS NOT NULL AND config_version > 0
                        AND octet_length(https_origin) BETWEEN 9 AND 1024
                        AND https_origin LIKE 'https://%'
                        AND https_origin !~ '[@?#[:space:]]'
                        AND octet_length(credential_ref) BETWEEN 1 AND 512
                        AND credential_ref ~ '^(vault|cyberark|aws|azure|gcp):'
                    )
                )
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'nms_import_plans_source_config_version_check'
                     AND conrelid = 'nms_import_plans'::regclass) THEN
        -- lock-ok: additive check on the small import-plan table.
        ALTER TABLE nms_import_plans
            ADD CONSTRAINT nms_import_plans_source_config_version_check
            CHECK (source_config_version >= 0) NOT VALID;
    END IF;
END $nms_source_shape$;
