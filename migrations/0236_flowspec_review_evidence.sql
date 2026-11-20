-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Both review shapes share the existing tenant-owned proposal row and RLS.
ALTER TABLE remediation_proposals ADD COLUMN IF NOT EXISTS flowspec_review jsonb;

DO $routing_review$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='public.remediation_proposals'::regclass
        AND conname='remediation_proposals_routing_review_v2') THEN
        ALTER TABLE remediation_proposals ADD CONSTRAINT remediation_proposals_routing_review_v2
          CHECK ((kind IN ('reroute_suggestion', 'traffic_shift_suggestion', 'open_ticket', 'trustctl_renewal')
                  AND rtbh_review IS NULL AND flowspec_review IS NULL)
              OR (kind='rtbh_review' AND flowspec_review IS NULL AND rtbh_review IS NOT NULL
                  AND jsonb_typeof(rtbh_review)='object' AND rtbh_review @> '{"version":1}'::jsonb
                  AND octet_length(rtbh_review::text)<=1048576)
              OR (kind='flowspec_review' AND rtbh_review IS NULL AND flowspec_review IS NOT NULL
                  AND jsonb_typeof(flowspec_review)='object' AND flowspec_review @> '{"version":1}'::jsonb
                  AND octet_length(flowspec_review::text)<=1048576)) NOT VALID;
    END IF;
END;
$routing_review$;

ALTER TABLE remediation_proposals DROP CONSTRAINT IF EXISTS remediation_proposals_rtbh_review_v1;
