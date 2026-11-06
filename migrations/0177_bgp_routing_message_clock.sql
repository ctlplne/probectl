-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Expand without inventing a clock for pre-existing generations. Readers and
-- heartbeat writers refuse a missing clock; the next complete generation is
-- born with one. The paired sequence prevents an older writer from advancing
-- data while leaving a newer writer's authority clock behind.
ALTER TABLE bgp_routing_views
    ADD COLUMN IF NOT EXISTS last_message_observed_at timestamptz;
ALTER TABLE bgp_routing_views
    ADD COLUMN IF NOT EXISTS message_clock_sequence bigint;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conrelid='bgp_routing_views'::regclass
          AND conname='fx5_route_message_clock_check'
    ) THEN
        ALTER TABLE bgp_routing_views ADD CONSTRAINT fx5_route_message_clock_check
            CHECK ((last_message_observed_at IS NULL AND message_clock_sequence IS NULL)
                OR (last_message_observed_at IS NOT NULL AND message_clock_sequence IS NOT NULL
                    AND last_message_observed_at>=observed_at
                    AND message_clock_sequence=last_sequence)) NOT VALID;
    END IF;
END $$;
ALTER TABLE bgp_routing_views VALIDATE CONSTRAINT fx5_route_message_clock_check;
