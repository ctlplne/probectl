-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- probectl:no-tx: prepare the exact tenant/context/parent lookup used by
-- entity-parent foreign-key cascades. Without this access path, deleting a
-- complete device population scans its siblings once for every deleted row.
CREATE INDEX CONCURRENTLY IF NOT EXISTS entities_tenant_context_parent_idx
    ON entities(tenant_id,context_id,parent_entity_id);
