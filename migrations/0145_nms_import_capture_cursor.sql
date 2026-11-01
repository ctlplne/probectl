-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- FX-2b: a request-driven live capture advances one source endpoint at a
-- time. Its cursor and short lease live on the existing FORCE-RLS plan row;
-- vendor bodies, credentials and URLs never enter this state.

-- lock-ok: import plans are new, low-volume operator rows. Constant defaults
-- are metadata-only additions; older export plans keep their inert state.
ALTER TABLE nms_import_plans
    ADD COLUMN IF NOT EXISTS capture_stage text NOT NULL DEFAULT 'devices',
    ADD COLUMN IF NOT EXISTS capture_group_cursor text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS capture_start_page bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS capture_start_row bigint NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS capture_lease_hash text,
    ADD COLUMN IF NOT EXISTS capture_lease_until timestamptz;

DO $nms_capture_cursor$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conname = 'nms_import_plans_capture_cursor_check'
                     AND conrelid = 'nms_import_plans'::regclass) THEN
        -- lock-ok: additive check on the small import-plan table; NOT VALID
        -- checks every new update without scanning older plans at rollout.
        ALTER TABLE nms_import_plans
            ADD CONSTRAINT nms_import_plans_capture_cursor_check CHECK (
                capture_stage IN ('devices', 'locations', 'groups', 'memberships',
                                  'rules', 'verify_devices', 'verify_locations',
                                  'verify_groups', 'verify_memberships',
                                  'verify_rules', 'complete')
                AND (capture_group_cursor = '' OR
                     (capture_group_cursor ~ '^[1-9][0-9]*$'
                      AND octet_length(capture_group_cursor) <= 20))
                AND capture_start_page >= 0 AND capture_start_row >= 0
                AND (capture_lease_hash IS NULL) = (capture_lease_until IS NULL)
                AND (capture_lease_hash IS NULL OR
                     capture_lease_hash ~ '^[0-9a-f]{64}$')
            ) NOT VALID;
    END IF;
END $nms_capture_cursor$;
