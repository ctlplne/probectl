// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import "fmt"

// Column catch-up happens first. Existing physical tables also need the
// observational-metadata CHECK that new LIKE INCLUDING ALL tables inherit.
func entityMetadataCheckPlan(schema string, tables []string) []string {
	for _, table := range TenantOwned(tables) {
		if table != "entity_evidence" {
			continue
		}
		child := quoteIdent(schema) + "." + quoteIdent(table)
		const name = "entity_evidence_snmp_system_description_check"
		return []string{fmt.Sprintf(`DO $entity_metadata_silo$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
    ALTER TABLE %s ADD CONSTRAINT %s CHECK
        (snmp_system_description IS NULL OR
         (source_kind='device_target' AND alias_kind='address'
          AND source_ref='snmp:configured-target'
          AND octet_length(snmp_system_description) BETWEEN 1 AND 1024
          AND translate(snmp_system_description, E'\t\n\r', '') !~ '[[:cntrl:]]')) NOT VALID;
END IF;
END;
$entity_metadata_silo$`, quoteLiteral(child), quoteLiteral(name), child, quoteIdent(name))}
	}
	return nil
}
