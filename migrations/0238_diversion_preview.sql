-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

ALTER TABLE remediation_proposals ADD COLUMN IF NOT EXISTS diversion_review jsonb;
ALTER TABLE remediation_proposals ADD COLUMN IF NOT EXISTS diversion_receipt jsonb;
ALTER TABLE remediation_proposals ADD COLUMN IF NOT EXISTS diversion_stopped_at timestamptz;

DO $diversion$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='public.remediation_proposals'::regclass
          AND conname='remediation_proposals_routing_review_v3') THEN
        ALTER TABLE remediation_proposals ADD CONSTRAINT remediation_proposals_routing_review_v3
          CHECK ((kind IN ('reroute_suggestion','traffic_shift_suggestion','open_ticket','trustctl_renewal')
                  AND rtbh_review IS NULL AND flowspec_review IS NULL AND diversion_review IS NULL)
              OR (kind='rtbh_review' AND flowspec_review IS NULL AND diversion_review IS NULL AND rtbh_review IS NOT NULL
                  AND jsonb_typeof(rtbh_review)='object' AND rtbh_review @> '{"version":1}'::jsonb
                  AND octet_length(rtbh_review::text)<=1048576)
              OR (kind='flowspec_review' AND rtbh_review IS NULL AND diversion_review IS NULL AND flowspec_review IS NOT NULL
                  AND jsonb_typeof(flowspec_review)='object' AND flowspec_review @> '{"version":1}'::jsonb
                  AND octet_length(flowspec_review::text)<=1048576)
              OR (kind='diversion_preview' AND rtbh_review IS NULL AND flowspec_review IS NULL AND diversion_review IS NOT NULL
                  AND jsonb_typeof(diversion_review)='object' AND diversion_review @> '{"version":1}'::jsonb
                  AND octet_length(diversion_review::text)<=32768)) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='public.remediation_proposals'::regclass
          AND conname='remediation_proposals_local_diversion_receipt_v1') THEN
        ALTER TABLE remediation_proposals ADD CONSTRAINT remediation_proposals_local_diversion_receipt_v1
          CHECK ((diversion_receipt IS NULL AND diversion_stopped_at IS NULL)
              OR (kind='diversion_preview' AND state='approved' AND diversion_receipt IS NOT NULL
                  AND jsonb_typeof(diversion_receipt)='object' AND diversion_receipt @> '{"connector":"local_preview"}'::jsonb
                  AND octet_length(diversion_receipt::text)<=2048
                  AND (diversion_receipt #>> '{action}' = diversion_review #>> '{review,candidate,action}') IS TRUE
                  AND (diversion_stopped_at IS NULL OR (diversion_receipt->>'action'='start') IS TRUE))) NOT VALID;
    END IF;
END;
$diversion$;

ALTER TABLE remediation_proposals DROP CONSTRAINT IF EXISTS remediation_proposals_routing_review_v2;
