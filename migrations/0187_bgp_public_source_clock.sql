-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Upstream RIB production time is independent of the collector receipt clock.
-- Unknown source clocks can be retained privately, never made current merely
-- by assigning an old source a new receipt timestamp.
ALTER TABLE bgp_public_snapshots ADD COLUMN IF NOT EXISTS source_observed_unix_nanos bigint;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='bgp_public_snapshots'::regclass
                   AND conname='fx5_public_snapshot_source_clock') THEN
        ALTER TABLE bgp_public_snapshots ADD CONSTRAINT fx5_public_snapshot_source_clock
            CHECK (source_observed_unix_nanos IS NULL OR source_observed_unix_nanos>=0);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='bgp_public_snapshots'::regclass
                   AND conname='fx5_public_snapshot_current_source_clock') THEN
        ALTER TABLE bgp_public_snapshots ADD CONSTRAINT fx5_public_snapshot_current_source_clock
            CHECK (state<>'current' OR source_observed_unix_nanos IS NOT NULL) NOT VALID;
    END IF;
END $$;
