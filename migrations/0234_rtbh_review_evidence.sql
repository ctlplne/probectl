-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Private evidence follows the proposal's tenant ownership and lifecycle.
-- Ordinary proposals retain a null review and their original kind rules.
ALTER TABLE remediation_proposals ADD COLUMN IF NOT EXISTS rtbh_review jsonb;

DO $rtbh_review$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.remediation_proposals'::regclass
        AND conname='remediation_proposals_rtbh_review_v1') THEN
        ALTER TABLE remediation_proposals ADD CONSTRAINT remediation_proposals_rtbh_review_v1
          CHECK ((kind IN ('reroute_suggestion', 'traffic_shift_suggestion', 'open_ticket', 'trustctl_renewal') AND rtbh_review IS NULL)
              OR (kind='rtbh_review' AND rtbh_review IS NOT NULL AND jsonb_typeof(rtbh_review)='object'
                  AND rtbh_review @> '{"version":1}'::jsonb AND octet_length(rtbh_review::text)<=1048576)) NOT VALID;
    END IF;
END;
$rtbh_review$;

ALTER TABLE remediation_proposals DROP CONSTRAINT IF EXISTS remediation_proposals_kind_check;
