-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Reuse the existing tenant/context foreign keys, FORCE RLS and review path.
-- lock-ok: additive replacement without a scan over existing imports.
ALTER TABLE nms_import_sources
    DROP CONSTRAINT IF EXISTS nms_import_sources_source_kind_check;
ALTER TABLE nms_import_sources
    ADD CONSTRAINT nms_import_sources_source_kind_check
    CHECK (source_kind IN ('librenms', 'zabbix', 'orion', 'prtg', 'sightline', 'defenseflow',
                          'device_discovery')) NOT VALID;
