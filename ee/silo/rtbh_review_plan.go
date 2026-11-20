// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"fmt"
	"slices"
)

func rtbhReviewStoragePlan(schema string, tables []string) []string {
	if !slices.Contains(TenantOwned(tables), "remediation_proposals") {
		return nil
	}
	child := quoteIdent(schema) + `."remediation_proposals"`
	return []string{fmt.Sprintf(`DO $rtbh_review_silo$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=%[1]s::regclass
        AND attname='rtbh_review' AND NOT attisdropped) THEN
        IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=%[1]s::regclass
            AND attname='flowspec_review' AND NOT attisdropped) THEN
            IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%[1]s::regclass
                AND conname IN ('remediation_proposals_routing_review_v2','remediation_proposals_routing_review_v3')) THEN
                ALTER TABLE %[2]s ADD CONSTRAINT remediation_proposals_routing_review_v2
                  CHECK ((kind IN ('reroute_suggestion','traffic_shift_suggestion','open_ticket','trustctl_renewal')
                          AND rtbh_review IS NULL AND flowspec_review IS NULL)
                      OR (kind='rtbh_review' AND flowspec_review IS NULL AND rtbh_review IS NOT NULL
                          AND jsonb_typeof(rtbh_review)='object' AND rtbh_review @> '{"version":1}'::jsonb
                          AND octet_length(rtbh_review::text)<=1048576)
                      OR (kind='flowspec_review' AND rtbh_review IS NULL AND flowspec_review IS NOT NULL
                          AND jsonb_typeof(flowspec_review)='object' AND flowspec_review @> '{"version":1}'::jsonb
                          AND octet_length(flowspec_review::text)<=1048576)) NOT VALID;
            END IF;
            ALTER TABLE %[2]s DROP CONSTRAINT IF EXISTS remediation_proposals_rtbh_review_v1;
        ELSIF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%[1]s::regclass
            AND conname='remediation_proposals_rtbh_review_v1') THEN
            ALTER TABLE %[2]s ADD CONSTRAINT remediation_proposals_rtbh_review_v1
              CHECK ((kind IN ('reroute_suggestion','traffic_shift_suggestion','open_ticket','trustctl_renewal') AND rtbh_review IS NULL)
                  OR (kind='rtbh_review' AND rtbh_review IS NOT NULL AND jsonb_typeof(rtbh_review)='object'
                      AND rtbh_review @> '{"version":1}'::jsonb AND octet_length(rtbh_review::text)<=1048576)) NOT VALID;
        END IF;
        ALTER TABLE %[2]s DROP CONSTRAINT IF EXISTS remediation_proposals_kind_check;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=%[1]s::regclass
        AND attname='flowspec_handoff' AND NOT attisdropped)
        AND NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%[1]s::regclass
            AND conname='remediation_proposals_flowspec_handoff_v1') THEN
        ALTER TABLE %[2]s ADD CONSTRAINT remediation_proposals_flowspec_handoff_v1
          CHECK ((flowspec_handoff IS NULL AND flowspec_withdraw_requested_at IS NULL)
              OR (kind='flowspec_review' AND state='approved' AND flowspec_handoff IS NOT NULL
                  AND jsonb_typeof(flowspec_handoff)='object' AND flowspec_handoff @> '{"version":1}'::jsonb
                  AND octet_length(flowspec_handoff::text)<=16384)) NOT VALID;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_attribute WHERE attrelid=%[1]s::regclass
        AND attname='diversion_review' AND NOT attisdropped) THEN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint
            WHERE conrelid=%[1]s::regclass
              AND conname='remediation_proposals_routing_review_v3') THEN
            ALTER TABLE %[2]s ADD CONSTRAINT remediation_proposals_routing_review_v3
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
            WHERE conrelid=%[1]s::regclass
              AND conname='remediation_proposals_local_diversion_receipt_v1') THEN
            ALTER TABLE %[2]s ADD CONSTRAINT remediation_proposals_local_diversion_receipt_v1
              CHECK ((diversion_receipt IS NULL AND diversion_stopped_at IS NULL)
                  OR (kind='diversion_preview' AND state='approved' AND diversion_receipt IS NOT NULL
                      AND jsonb_typeof(diversion_receipt)='object' AND diversion_receipt @> '{"connector":"local_preview"}'::jsonb
                      AND octet_length(diversion_receipt::text)<=2048
                      AND (diversion_receipt #>> '{action}' = diversion_review #>> '{review,candidate,action}') IS TRUE
                      AND (diversion_stopped_at IS NULL OR (diversion_receipt->>'action'='start') IS TRUE))) NOT VALID;
        END IF;
        ALTER TABLE %[2]s DROP CONSTRAINT IF EXISTS remediation_proposals_routing_review_v2;
        CREATE UNIQUE INDEX IF NOT EXISTS remediation_proposals_active_diversion_prefix
        ON %[2]s (tenant_id, (diversion_review #>> '{review,candidate,prefix}'))
        WHERE kind='diversion_preview' AND state='approved' AND diversion_receipt->>'action'='start'
          AND diversion_stopped_at IS NULL;
    END IF;
END;
$rtbh_review_silo$`, quoteLiteral(child), child)}
}
