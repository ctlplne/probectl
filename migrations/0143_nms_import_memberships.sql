-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-2b: 0141 was already applied by draft checkouts before membership
-- capture was added. A fresh install gets the expanded checks in 0141; this
-- forward step converges those earlier databases without rewriting history.
-- Both are small, tenant-scoped operator plan tables, not telemetry hot paths.
-- Each DROP+ADD pair is atomic in the migration transaction; NOT VALID avoids
-- scanning existing rows while the new superset still checks every new write.

-- lock-ok: this briefly replaces a check on the small import-page plan table;
-- the replacement is an additive superset and the transaction exposes no gap.
ALTER TABLE nms_import_pages
    DROP CONSTRAINT IF EXISTS nms_import_pages_resource_kind_check;
ALTER TABLE nms_import_pages
    ADD CONSTRAINT nms_import_pages_resource_kind_check
    CHECK (resource_kind IN ('devices', 'locations', 'nodes', 'groups', 'memberships', 'rules', 'hosts', 'probes')) NOT VALID;

-- lock-ok: this briefly replaces a check on the small import-row plan table;
-- the replacement is an additive superset and the transaction exposes no gap.
ALTER TABLE nms_import_rows
    DROP CONSTRAINT IF EXISTS nms_import_rows_object_kind_check;
ALTER TABLE nms_import_rows
    ADD CONSTRAINT nms_import_rows_object_kind_check
    CHECK (object_kind IN ('device', 'site', 'group', 'membership', 'poll_setting', 'alert_rule')) NOT VALID;
