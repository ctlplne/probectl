// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import "fmt"

// LIKE omits foreign keys. Both provision and catch-up must bind grants and
// bindings to a role in this physical schema with the same tenant identity.
func rbacRoleReferencePlan(schema string, tables []string) []string {
	owned := map[string]bool{}
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	if !owned["roles"] {
		return nil
	}
	q := quoteIdent(schema)
	plan := []string{"CREATE UNIQUE INDEX IF NOT EXISTS roles_tenant_identity_uidx ON " + q + `."roles" (tenant_id,id)`}
	for _, name := range []string{"role_permissions", "role_bindings"} {
		if !owned[name] {
			continue
		}
		child, constraint := q+"."+quoteIdent(name), name+"_tenant_role_fk"
		plan = append(plan, fmt.Sprintf(`DO $rbac_role_reference$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
 ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (tenant_id,role_id) REFERENCES %s."roles" (tenant_id,id) ON DELETE CASCADE NOT VALID;
END IF;
END $rbac_role_reference$`, quoteLiteral(child), quoteLiteral(constraint), child, quoteIdent(constraint), q),
			"ALTER TABLE "+child+" VALIDATE CONSTRAINT "+quoteIdent(constraint))
	}
	return plan
}
