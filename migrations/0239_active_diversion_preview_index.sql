-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- probectl:no-tx: index an existing tenant-owned table without blocking writes
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS remediation_proposals_active_diversion_prefix
    ON public.remediation_proposals (tenant_id, (diversion_review #>> '{review,candidate,prefix}'))
    WHERE kind='diversion_preview' AND state='approved' AND diversion_receipt->>'action'='start'
      AND diversion_stopped_at IS NULL;
