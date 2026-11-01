-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- probectl:no-tx: build the composite path-binding FK target online before
-- the transactional FX-2 registry migration references it.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS tests_tenant_id_id_uidx
    ON tests(tenant_id, id);
