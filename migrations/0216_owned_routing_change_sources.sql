-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Original owned-router references extend the existing tenant-owned change
-- stream. Webhook writes leave both columns NULL. Private source metadata is
-- never selected into the public event projection.
-- lock-ok: additive nullable columns; no rewrite of existing event bodies.
ALTER TABLE change_events ADD COLUMN IF NOT EXISTS routing jsonb;
ALTER TABLE change_events ADD COLUMN IF NOT EXISTS routing_source jsonb;
