-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- A configured, fully replay-verified source may propose a missing member
-- as an inert plan row. Only an explicit reviewed remove choice can delete
-- its exact source-keyed member; a file or partial capture has no authority.

-- lock-ok: import plans are new low-volume operator tables. These additive
-- supersets are installed transactionally with NOT VALID so existing plans
-- are not scanned and new writes are checked immediately.
ALTER TABLE nms_import_pages
    DROP CONSTRAINT IF EXISTS nms_import_pages_resource_kind_check;
ALTER TABLE nms_import_pages
    ADD CONSTRAINT nms_import_pages_resource_kind_check
    CHECK (resource_kind IN ('devices', 'locations', 'nodes', 'groups',
                            'memberships', 'member_removals', 'rules', 'hosts', 'probes')) NOT VALID;

ALTER TABLE nms_import_rows
    DROP CONSTRAINT IF EXISTS nms_import_rows_action_check;
ALTER TABLE nms_import_rows
    ADD CONSTRAINT nms_import_rows_action_check
    CHECK (action IN ('captured', 'create', 'update', 'remove',
                     'conflict', 'skip', 'unmapped')) NOT VALID;

ALTER TABLE nms_import_rows
    DROP CONSTRAINT IF EXISTS nms_import_rows_target_fingerprint_check;
ALTER TABLE nms_import_rows
    ADD CONSTRAINT nms_import_rows_target_fingerprint_check
    CHECK (target_fingerprint IS NULL OR
           (action IN ('update', 'remove') AND
            target_fingerprint ~ '^[0-9a-f]{64}$')) NOT VALID;

ALTER TABLE nms_import_rows
    ADD COLUMN IF NOT EXISTS target_group_revision bigint;
DO $nms_member_revision$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='nms_import_rows'::regclass
                     AND conname='nms_import_rows_target_group_revision_check') THEN
        ALTER TABLE nms_import_rows
            ADD CONSTRAINT nms_import_rows_target_group_revision_check
            CHECK (target_group_revision IS NULL OR
                   (action='remove' AND target_group_revision>=0)) NOT VALID;
    END IF;
END $nms_member_revision$;

ALTER TABLE nms_import_groups
    ADD COLUMN IF NOT EXISTS revision bigint NOT NULL DEFAULT 0;
ALTER TABLE nms_import_groups
    ADD COLUMN IF NOT EXISTS revision_plan_id uuid;
ALTER TABLE nms_import_groups
    ADD COLUMN IF NOT EXISTS revision_plan_delta bigint NOT NULL DEFAULT 0;
DO $nms_group_revision$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='nms_import_groups'::regclass
                     AND conname='nms_import_groups_revision_check') THEN
        ALTER TABLE nms_import_groups
            ADD CONSTRAINT nms_import_groups_revision_check
            CHECK (revision>=0 AND revision_plan_delta>=0 AND
                   ((revision_plan_id IS NULL)=(revision_plan_delta=0))) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='nms_import_groups'::regclass
                     AND conname='nms_import_groups_revision_plan_fk') THEN
        ALTER TABLE nms_import_groups
            ADD CONSTRAINT nms_import_groups_revision_plan_fk
            FOREIGN KEY (tenant_id,context_id,revision_plan_id,source_id)
            REFERENCES nms_import_plans(tenant_id,context_id,id,source_id)
            ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED NOT VALID;
    END IF;
END $nms_group_revision$;
