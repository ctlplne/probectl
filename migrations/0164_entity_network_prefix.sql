-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Explicit operator network metadata only. Never infer a range from a label
-- or add a source identity alias; legacy rows remain NULL.
-- lock-ok: nullable metadata-only ADD; NOT VALID avoids a historical scan
-- while holding the DDL lock and still checks every new/updated row.
ALTER TABLE entities ADD COLUMN IF NOT EXISTS network_prefix cidr;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='entities'::regclass
          AND conname='entities_network_prefix_kind_check') THEN
        ALTER TABLE entities ADD CONSTRAINT entities_network_prefix_kind_check
            CHECK (network_prefix IS NULL OR kind='prefix') NOT VALID;
    END IF;
END $$;
