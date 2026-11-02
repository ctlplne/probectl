-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- probectl:no-tx: the pre-existing identity tables need online FK target
-- indexes before the transactional FX-3 tag migration can reference them.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS entities_tenant_context_id_kind_uidx
    ON entities(tenant_id, context_id, id, kind);
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS entity_sources_tenant_context_identity_uidx
    ON entity_source_contexts
        (tenant_id, context_id, agent_id, source_kind, source_ref);
