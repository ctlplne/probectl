-- SPDX-License-Identifier: BUSL-1.1
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- The scoped reader rechecks the artifact before using it as evidence.
-- lock-ok: additive nullable receipt identifier; existing rows need no rewrite.
ALTER TABLE prospect_engagements ADD COLUMN IF NOT EXISTS assessment_artifact_id text;
