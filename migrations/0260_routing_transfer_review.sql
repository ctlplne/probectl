-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Preserve existing proposal rows and enforce the dedicated approval payload
-- on every new routing-transfer decision, including writes by older replicas.
ALTER TABLE public.remediation_proposals ADD COLUMN IF NOT EXISTS routing_transfer_review jsonb;
ALTER TABLE public.remediation_proposals ADD COLUMN IF NOT EXISTS routing_transfer_approval jsonb;

DO $routing_transfer$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='public.remediation_proposals'::regclass
          AND conname='remediation_proposals_routing_review_v4') THEN
        ALTER TABLE public.remediation_proposals ADD CONSTRAINT remediation_proposals_routing_review_v4
          CHECK (((kind IN ('reroute_suggestion','traffic_shift_suggestion','open_ticket','trustctl_renewal')
                   AND rtbh_review IS NULL AND flowspec_review IS NULL AND diversion_review IS NULL AND routing_transfer_review IS NULL)
              OR (kind='rtbh_review' AND flowspec_review IS NULL AND diversion_review IS NULL AND routing_transfer_review IS NULL
                  AND rtbh_review IS NOT NULL AND jsonb_typeof(rtbh_review)='object'
                  AND rtbh_review @> '{"version":1}'::jsonb AND octet_length(rtbh_review::text)<=1048576)
              OR (kind='flowspec_review' AND rtbh_review IS NULL AND diversion_review IS NULL AND routing_transfer_review IS NULL
                  AND flowspec_review IS NOT NULL AND jsonb_typeof(flowspec_review)='object'
                  AND flowspec_review @> '{"version":1}'::jsonb AND octet_length(flowspec_review::text)<=1048576)
              OR (kind='diversion_preview' AND rtbh_review IS NULL AND flowspec_review IS NULL AND routing_transfer_review IS NULL
                  AND diversion_review IS NOT NULL AND jsonb_typeof(diversion_review)='object'
                  AND diversion_review @> '{"version":1}'::jsonb AND octet_length(diversion_review::text)<=32768)
              OR (kind='routing_transfer_review' AND rtbh_review IS NULL AND flowspec_review IS NULL AND diversion_review IS NULL
                  AND routing_transfer_review IS NOT NULL AND jsonb_typeof(routing_transfer_review)='object'
                  AND routing_transfer_review @> '{"version":1}'::jsonb
                  AND (routing_transfer_review #>> '{review,fingerprint}') ~ '^[0-9a-f]{64}$'
                  AND jsonb_typeof(routing_transfer_review #> '{review,expires_at}')='string'
                  AND octet_length(routing_transfer_review::text)<=1048576)) IS TRUE) NOT VALID;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='public.remediation_proposals'::regclass
          AND conname='remediation_proposals_routing_transfer_approval_v1') THEN
        ALTER TABLE public.remediation_proposals ADD CONSTRAINT remediation_proposals_routing_transfer_approval_v1
          CHECK (((routing_transfer_approval IS NULL AND (kind<>'routing_transfer_review' OR state IN ('proposed','rejected')))
              OR (kind='routing_transfer_review' AND state IN ('approved','applied') AND routing_transfer_approval IS NOT NULL
                  AND jsonb_typeof(routing_transfer_approval)='object' AND routing_transfer_approval @> '{"version":1}'::jsonb
                  AND proposed_user_id IS NOT NULL
                  AND (routing_transfer_approval->>'review_fingerprint')=(routing_transfer_review #>> '{review,fingerprint}')
                  AND (routing_transfer_approval->>'approved_by_user_id') ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                  AND (routing_transfer_approval->>'approved_by_user_id')<>proposed_user_id::text
                  AND jsonb_typeof(routing_transfer_approval->'approved_at')='string'
                  AND jsonb_typeof(routing_transfer_approval->'expires_at')='string'
                  AND octet_length(routing_transfer_approval::text)<=2048)) IS TRUE) NOT VALID;
    END IF;
END;
$routing_transfer$;

ALTER TABLE public.remediation_proposals DROP CONSTRAINT IF EXISTS remediation_proposals_routing_review_v3;
