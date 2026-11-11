// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import "fmt"

func capacityAgreementStoragePlan(schema string, tables []string) []string {
	owned := map[string]bool{}
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	q := quoteIdent(schema)
	var plan []string
	for _, key := range []struct{ child, name, columns, parent, parentColumns string }{
		{"flow_capacity_agreements", "fx6_agreement_tenant_fk", "tenant_id", "public.tenants", "id"},
		{"flow_capacity_agreement_revisions", "fx6_agreement_revision_fk", "tenant_id,agreement_id", "flow_capacity_agreements", "tenant_id,id"},
		{"flow_capacity_agreement_refs", "fx6_agreement_ref_revision_fk", "tenant_id,agreement_id,version", "flow_capacity_agreement_revisions", "tenant_id,agreement_id,version"},
		{"flow_capacity_agreement_refs", "fx6_agreement_ref_interface_fk", "tenant_id,context_id,interface_id,interface_kind", "entities", "tenant_id,context_id,id,kind"},
		{"flow_capacity_agreement_refs", "fx6_agreement_ref_tag_fk", "tenant_id,tag_id", "tenant_tag_definitions", "tenant_id,id"},
	} {
		if !owned[key.child] {
			continue
		}
		child, parent := q+"."+quoteIdent(key.child), q+"."+quoteIdent(key.parent)
		if key.parent == "public.tenants" {
			parent = "public.tenants"
		}
		plan = append(plan, fmt.Sprintf(`DO $fx6_agreement_fk$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
 ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s (%s) ON DELETE CASCADE;
END IF;
END $fx6_agreement_fk$`, quoteLiteral(child), quoteLiteral(key.name), child, quoteIdent(key.name), key.columns, parent, key.parentColumns))
	}
	for _, table := range []string{"flow_capacity_agreement_revisions", "flow_capacity_agreement_refs"} {
		if owned[table] {
			plan = append(plan, "REVOKE UPDATE ON "+q+"."+quoteIdent(table)+" FROM probectl_app,probectl_provider")
		}
	}
	if owned["flow_capacity_agreement_revisions"] {
		child := q + `."flow_capacity_agreement_revisions"`
		for _, trigger := range []struct{ name, event, function string }{
			{"capacity_agreement_reference", "INSERT", "public.probectl_capacity_agreement_reference"},
			{"capacity_agreement_head_delete", "DELETE", "public.probectl_capacity_agreement_head_delete"},
		} {
			plan = append(plan, "DROP TRIGGER IF EXISTS "+trigger.name+" ON "+child,
				"CREATE TRIGGER "+trigger.name+" AFTER "+trigger.event+" ON "+child+" FOR EACH ROW EXECUTE FUNCTION "+trigger.function+"()",
				"ALTER TABLE "+child+" ENABLE ALWAYS TRIGGER "+trigger.name)
		}
	}
	return plan
}
