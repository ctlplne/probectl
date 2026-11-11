// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import (
	"strings"
	"testing"
)

func TestCapacityAgreementStoragePlanKeepsScopedReferencesAndImmutableTerms(t *testing.T) {
	const schema = "t_11111111111141118111111111111111"
	tables := []string{"flow_capacity_agreements", "flow_capacity_agreement_revisions", "flow_capacity_agreement_refs", "entities", "tenant_tag_definitions"}
	plan := strings.Join(capacityAgreementStoragePlan(schema, tables), "\n")
	for _, required := range []string{`REFERENCES "` + schema + `"."entities" (tenant_id,context_id,id,kind)`,
		`REFERENCES "` + schema + `"."tenant_tag_definitions" (tenant_id,id)`,
		`REFERENCES "` + schema + `"."flow_capacity_agreement_revisions" (tenant_id,agreement_id,version)`,
		`REVOKE UPDATE ON "` + schema + `"."flow_capacity_agreement_revisions"`,
		`ENABLE ALWAYS TRIGGER capacity_agreement_reference`, `ENABLE ALWAYS TRIGGER capacity_agreement_head_delete`} {
		if !strings.Contains(plan, required) {
			t.Fatal("silo agreement copy lost scoped ownership or immutable/lifecycle semantics", required)
		}
	}
	if strings.Contains(plan, "REFERENCES public.entities") || strings.Contains(plan, "REFERENCES public.tenant_tag_definitions") {
		t.Fatal("agreement references escaped their physical tenant silo")
	}
}
