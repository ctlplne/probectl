// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import "fmt"

// Existing physical tables receive the same typed metadata boundary as newly
// provisioned LIKE INCLUDING ALL tables, after generic column catch-up.
func entityNetworkPrefixCheckPlan(schema string, tables []string) []string {
	for _, table := range TenantOwned(tables) {
		if table == "entities" {
			child := quoteIdent(schema) + "." + quoteIdent(table)
			const name = "entities_network_prefix_kind_check"
			return []string{fmt.Sprintf(`DO $entity_network_silo$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
    ALTER TABLE %s ADD CONSTRAINT %s
        CHECK (network_prefix IS NULL OR kind='prefix') NOT VALID;
END IF;
END;
$entity_network_silo$`, quoteLiteral(child), quoteLiteral(name), child, quoteIdent(name))}
		}
	}
	return nil
}
