-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- probectl:no-tx: retain indexed tenant/destination FK and cleanup reads
-- before replacing the former single-test unique constraint. Build online so
-- the existing path binding writers remain available during this preparation.
CREATE INDEX CONCURRENTLY IF NOT EXISTS entity_path_test_target_context_idx
    ON entity_path_test_contexts(tenant_id,path_target,context_id);
