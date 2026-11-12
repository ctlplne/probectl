-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Configuration remains on existing tenant-owned FORCE-RLS alert rows.
-- A policy never stops collection or changes the rule's detection predicate.
-- lock-ok: nullable additive metadata; existing alert/source rows are unchanged.
ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS dependency_policy jsonb;
