-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- The complete observation clock belongs to the existing tenant rule. Source
-- edits clear it and every window commit matches tenant and rule revision.
-- lock-ok: additive nullable column; no stored rule is rewritten.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS seasonal_last_window_at timestamptz;

-- Private reader requirements on the existing FORCE-RLS tenant receipt.
-- lock-ok: additive nullable column; no stored receipt is rewritten.
ALTER TABLE alert_evaluation_receipts
    ADD COLUMN IF NOT EXISTS seasonal_flow_scope bytea;
