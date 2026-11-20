-- SPDX-License-Identifier: BUSL-1.1
--
-- Use of this source code is governed by the Business Source License 1.1
-- in the LICENSE file at the root of this repository; on its Change Date
-- each version converts to the Mozilla Public License 2.0.

-- Store the exact handoff beside its existing tenant-owned decision.
ALTER TABLE remediation_proposals ADD COLUMN IF NOT EXISTS flowspec_handoff jsonb;
ALTER TABLE remediation_proposals ADD COLUMN IF NOT EXISTS flowspec_withdraw_requested_at timestamptz;

DO $handoff$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
        WHERE conrelid='public.remediation_proposals'::regclass
          AND conname='remediation_proposals_flowspec_handoff_v1') THEN
        ALTER TABLE remediation_proposals ADD CONSTRAINT remediation_proposals_flowspec_handoff_v1
          CHECK ((flowspec_handoff IS NULL AND flowspec_withdraw_requested_at IS NULL)
              OR (kind='flowspec_review' AND state='approved' AND flowspec_handoff IS NOT NULL
                  AND jsonb_typeof(flowspec_handoff)='object'
                  AND flowspec_handoff @> '{"version":1}'::jsonb
                  AND octet_length(flowspec_handoff::text)<=16384)) NOT VALID;
    END IF;
END;
$handoff$;
