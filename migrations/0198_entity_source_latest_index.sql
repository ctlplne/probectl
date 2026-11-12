-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- probectl:no-tx: build the exact-source latest-observation access path online
-- while existing evidence readers and writers remain available.
CREATE INDEX CONCURRENTLY IF NOT EXISTS entity_evidence_tenant_source_latest_idx
    ON entity_evidence
       (tenant_id, context_id, agent_id, source_kind, configured_ref,
        observed_at DESC, id);
