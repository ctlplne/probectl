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

func TestInterfaceRoleStoragePlanKeepsLocalKindAndTenantForeignKeys(t *testing.T) {
	plan := strings.Join(ProvisionPlan("t_11111111111141118111111111111111", []string{"entity_contexts", "entities", "interface_role_policies", "interface_role_overrides"}), "\n")
	for _, want := range []string{`"fx4_role_policy_tenant_fk"`, `"fx4_role_policy_context_fk"`, `"fx4_role_override_tenant_fk"`,
		`FOREIGN KEY (tenant_id,context_id,interface_id,entity_kind) REFERENCES "t_11111111111141118111111111111111"."entities" (tenant_id,context_id,id,kind)`,
		`REFERENCES "t_11111111111141118111111111111111"."entity_contexts" (tenant_id,id)`} {
		if !strings.Contains(plan, want) {
			t.Fatal("role copy omitted tenant/context/interface-kind storage binding", want)
		}
	}
	if strings.Contains(plan, "REFERENCES public.entities") || strings.Contains(plan, "REFERENCES public.entity_contexts") {
		t.Fatal("role configuration silently referenced another storage target")
	}
}
