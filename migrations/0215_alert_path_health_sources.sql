-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Existing tenant-owned FORCE-RLS alert configuration; no telemetry/model rows.
-- Managed schemas receive the same nullable addition through schema catch-up.
-- lock-ok: additive nullable column; no alert or source history is rewritten.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS path_health_source jsonb;
