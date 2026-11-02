-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- A reviewed live source needs a fresh, endpoint-by-endpoint receipt pass
-- before a destination chunk may commit. These columns carry only cursor
-- state and fixed digests, never source bodies or credentials.

-- lock-ok: import plans and their endpoint receipts are new, low-volume
-- operator tables. Nullable additions are metadata-only and leave older
-- export plans inert.
ALTER TABLE nms_import_capture_steps
    ADD COLUMN IF NOT EXISTS apply_verified_at timestamptz;

ALTER TABLE nms_import_plans
    ADD COLUMN IF NOT EXISTS apply_verified_review_hash text,
    ADD COLUMN IF NOT EXISTS apply_verified_at timestamptz;

DO $nms_apply_verification$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='nms_import_plans'::regclass
                     AND conname='nms_import_plans_apply_verified_hash_check') THEN
        -- lock-ok: NOT VALID checks new writes without scanning old plans.
        ALTER TABLE nms_import_plans
            ADD CONSTRAINT nms_import_plans_apply_verified_hash_check CHECK (
                (apply_verified_review_hash IS NULL) = (apply_verified_at IS NULL)
                AND (apply_verified_review_hash IS NULL OR
                     apply_verified_review_hash ~ '^[0-9a-f]{64}$')
            ) NOT VALID;
    END IF;
END $nms_apply_verification$;
