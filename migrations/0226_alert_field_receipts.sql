-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Exact field observations and their original reader requirements remain
-- private to the authorized source receipt reader on this FORCE-RLS table.
-- lock-ok: additive nullable column; existing receipts need no rewrite.
ALTER TABLE alert_evaluation_receipts ADD COLUMN IF NOT EXISTS field_change_receipt bytea;
