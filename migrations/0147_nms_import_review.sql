-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- An operator reviews every redacted source row before an import can write a
-- destination. The hash binds the complete choice set to the sealed snapshot.
ALTER TABLE nms_import_rows ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;
ALTER TABLE nms_import_plans ADD COLUMN IF NOT EXISTS review_hash text;
DO $nms_review_hash$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='nms_import_rows'::regclass
                     AND conname='nms_import_rows_review_choice_check') THEN
        ALTER TABLE nms_import_rows ADD CONSTRAINT nms_import_rows_review_choice_check
            CHECK ((action='captured' AND reviewed_at IS NULL) OR
                   (action<>'captured' AND reviewed_at IS NOT NULL)) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='nms_import_plans'::regclass
                     AND conname='nms_import_plans_review_hash_check') THEN
        ALTER TABLE nms_import_plans ADD CONSTRAINT nms_import_plans_review_hash_check
            CHECK (review_hash IS NULL OR review_hash ~ '^[0-9a-f]{64}$') NOT VALID;
    END IF;
END $nms_review_hash$;
