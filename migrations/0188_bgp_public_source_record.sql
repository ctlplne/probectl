-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Preserve the original MRT peer table even for a source with zero peers.
ALTER TABLE bgp_public_snapshots ADD COLUMN IF NOT EXISTS source_record bytea;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                   WHERE conrelid='bgp_public_snapshots'::regclass
                     AND conname='fx5_public_snapshot_source_record') THEN
        ALTER TABLE bgp_public_snapshots ADD CONSTRAINT fx5_public_snapshot_source_record
            CHECK (source_record IS NULL OR octet_length(source_record)>=12) NOT VALID;
    END IF;
END $$;
