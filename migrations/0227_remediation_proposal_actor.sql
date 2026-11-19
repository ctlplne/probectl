-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Retain the verified proposing account for later review. Historic rows keep
-- their display labels and require a new proposal before approval.
ALTER TABLE remediation_proposals ADD COLUMN IF NOT EXISTS proposed_user_id uuid;
