-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- A declared public peer/family occurs once in its source snapshot, including
-- private staging. Legacy unbound private views are unaffected.
CREATE UNIQUE INDEX IF NOT EXISTS bgp_routing_views_public_slot_idx
    ON bgp_routing_views(tenant_id,context_id,public_snapshot_id,peer_key,afi,safi)
    WHERE public_snapshot_id IS NOT NULL;
