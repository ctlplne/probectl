// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

// A normalized target anchor and its test references are one storage guard.
// LIKE INCLUDING ALL copies neither their FKs nor the runtime triggers, so
// install them after registry/tag relations on both fresh and existing silos.
func pathTargetContextPlan(schema string, tables []string) []string {
	if schemaTenantID(schema) == "" {
		return nil
	}
	owned := map[string]bool{}
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	if !owned["entity_contexts"] || !owned["entity_path_test_contexts"] {
		return nil
	}
	return []string{"SELECT public.probectl_install_path_target_contexts(" + quoteLiteral(schema) + ")"}
}
