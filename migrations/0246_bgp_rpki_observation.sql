-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Capture a local validator result with the original owned path. Existing
-- rows have no validator evidence and retain their original meanings.
ALTER TABLE bgp_as_path_history ADD COLUMN IF NOT EXISTS rpki_observation jsonb
    CHECK (rpki_observation IS NULL OR (
           source_kind = 'router_bmp' AND current_path IS NOT NULL
           AND jsonb_typeof(rpki_observation) = 'object' AND octet_length(rpki_observation::text) <= 262144));
