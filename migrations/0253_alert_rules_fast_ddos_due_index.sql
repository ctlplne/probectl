-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.
-- probectl:no-tx: build the scheduler's due-rule index while alert writers remain online.

CREATE INDEX CONCURRENTLY IF NOT EXISTS alert_rules_fast_ddos_due_idx
    ON public.alert_rules (tenant_id, (COALESCE(query_next_eval_at, '-infinity'::timestamptz)))
    WHERE enabled AND query_source#>>'{condition,mode}'='ddos_assessment'
      AND query_source#>>'{condition,ddos,period_seconds}' IN ('5','10');
