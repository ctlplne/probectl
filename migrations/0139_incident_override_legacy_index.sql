-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- probectl:no-tx: 0138 is complete and durable before this runs. Retrying a
-- crashed drop leaves its valid scoped replacement intact.
DROP INDEX CONCURRENTLY IF EXISTS incident_correlation_overrides_one_active_match_uidx;
