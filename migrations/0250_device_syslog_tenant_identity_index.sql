-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- probectl:no-tx: build the tenant-scoped reference target online while syslog is ingested.

CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS device_syslog_tenant_id_id_idx
    ON public.device_syslog(tenant_id, id);
