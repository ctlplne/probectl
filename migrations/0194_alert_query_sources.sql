-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Existing tenant-owned FORCE-RLS alert rows retain source configuration and
-- opaque group state. No new telemetry store or source-read credential exists.
-- Nullable/defaulted additions also flow through managed-schema catch-up.
-- lock-ok: additive columns; no historical alert or source result is rewritten.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS query_source jsonb;
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS query_group_state jsonb;
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS query_state_version bigint NOT NULL DEFAULT 0;
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS query_next_eval_at timestamptz;
