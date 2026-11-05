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
		const systemName = "entity_evidence_snmp_system_name_check"
		const agentAddresses = "entity_evidence_agent_addresses_check"
		const snmpPrefixes = "entity_evidence_snmp_prefix_snapshot_check"
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
$entity_metadata_silo$`, quoteLiteral(child), quoteLiteral(name), child, quoteIdent(name)),
			fmt.Sprintf(`DO $entity_name_silo$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
    ALTER TABLE %s ADD CONSTRAINT %s CHECK
        (snmp_system_name IS NULL OR
         (source_kind='device_target' AND alias_kind='address'
          AND source_ref='snmp:configured-target'
          AND octet_length(snmp_system_name)<=1024
          AND snmp_system_name !~ '[[:cntrl:]]')) NOT VALID;
END IF;
END;
$entity_name_silo$`, quoteLiteral(child), quoteLiteral(systemName), child, quoteIdent(systemName)),
			fmt.Sprintf(`DO $entity_agent_addresses_silo$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
    ALTER TABLE %s ADD CONSTRAINT %s CHECK
        (agent_addresses IS NULL OR
         (source_kind='agent_site' AND alias_kind='agent_site_id'
          AND configured_ref=agent_id AND source_ref='agent:label:site'
          AND public.probectl_agent_addresses_valid(agent_addresses))) NOT VALID;
END IF;
END;
$entity_agent_addresses_silo$`, quoteLiteral(child), quoteLiteral(agentAddresses), child, quoteIdent(agentAddresses)),
			fmt.Sprintf(`DO $entity_snmp_prefix_silo$ BEGIN
IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname=%s) THEN
    ALTER TABLE %s ADD CONSTRAINT %s CHECK
        (snmp_interface_prefixes IS NULL OR
         (source_kind='device_target' AND alias_kind='address'
          AND source_ref='snmp:configured-target'
          AND public.probectl_snmp_prefix_snapshot_valid(snmp_interface_prefixes))) NOT VALID;
END IF;
END;
$entity_snmp_prefix_silo$`, quoteLiteral(child), quoteLiteral(snmpPrefixes), child, quoteIdent(snmpPrefixes))}
	}
	return nil
}
