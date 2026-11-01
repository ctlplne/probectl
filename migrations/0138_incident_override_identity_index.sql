-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- probectl:no-tx: build the new index while the old unique index still
-- protects writers. Drop an invalid/incomplete prior attempt before retrying.
-- Migration 0139 removes the old index only after this migration is recorded.
DROP INDEX CONCURRENTLY IF EXISTS incident_correlation_overrides_one_active_identity_uidx;
CREATE UNIQUE INDEX CONCURRENTLY incident_correlation_overrides_one_active_identity_uidx
    ON incident_correlation_overrides
       (tenant_id, source_incident_id, plane, kind, target, prefix,
        identity_lookup_attempted, entity_context_id, entity_id)
    NULLS NOT DISTINCT WHERE active;
