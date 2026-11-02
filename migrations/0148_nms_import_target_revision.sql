-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- A reviewed exact merge target is frozen by content and revision. Apply
-- refuses a target that changed after the operator selected it.
-- The CHECK allows NULL during expand so the prior binary can still write;
-- the new review service requires a fingerprint before finalizing an update.
ALTER TABLE nms_import_rows ADD COLUMN IF NOT EXISTS target_fingerprint text;
DO $nms_import_target_revision$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='nms_import_rows'::regclass
                     AND conname='nms_import_rows_target_fingerprint_check') THEN
        ALTER TABLE nms_import_rows
            ADD CONSTRAINT nms_import_rows_target_fingerprint_check
            CHECK (target_fingerprint IS NULL OR
                   (action = 'update' AND target_fingerprint ~ '^[0-9a-f]{64}$')) NOT VALID;
    END IF;
END $nms_import_target_revision$;
