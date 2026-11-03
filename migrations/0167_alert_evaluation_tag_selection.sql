-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Actual selection evidence stays on the existing FORCE-RLS transition row.
-- Legacy rows remain NULL: a configuration binding is not execution proof.
-- lock-ok: nullable ADD and NOT VALID CHECK avoid a historical table scan.
ALTER TABLE alert_evaluation_receipts ADD COLUMN IF NOT EXISTS tag_selection jsonb;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='alert_evaluation_receipts'::regclass
          AND conname='alert_evaluation_tag_selection_shape') THEN
        ALTER TABLE alert_evaluation_receipts ADD CONSTRAINT alert_evaluation_tag_selection_shape
            CHECK (tag_selection IS NULL OR
                (jsonb_typeof(tag_selection)='object'
                 AND octet_length(tag_selection::text)<=1024)) NOT VALID;
    END IF;
END $$;
