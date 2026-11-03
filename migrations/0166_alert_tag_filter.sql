-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Same tenant-owned FORCE-RLS row, nullable for unchanged legacy rules.
-- lock-ok: nullable ADD and NOT VALID CHECK do not scan historical rules.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS tag_filter jsonb;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='alert_rules'::regclass AND conname='alert_rules_tag_filter_shape') THEN
        ALTER TABLE alert_rules ADD CONSTRAINT alert_rules_tag_filter_shape
            CHECK (tag_filter IS NULL OR
                (jsonb_typeof(tag_filter)='object'
                 AND octet_length(tag_filter::text)<=8388608)) NOT VALID;
    END IF;
END $$;
