-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Existing tenant-owned FORCE-RLS alert configuration. No copies of telemetry
-- or trained state are written. Silo catch-up applies the nullable addition.
-- lock-ok: additive nullable column; no stored rule is rewritten.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS seasonal_source jsonb;

-- Existing bounded FORCE-RLS transition receipt. Historical rolling receipts
-- keep their original shape.
-- lock-ok: additive nullable column; no stored receipt is rewritten.
ALTER TABLE alert_evaluation_receipts ADD COLUMN IF NOT EXISTS seasonal_evidence jsonb;
