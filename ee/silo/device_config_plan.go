// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package silo

import "fmt"

// LIKE omits foreign keys; existing silos also need the staged completeness
// check. Neither statement scans retained archives under the DDL transaction.
func deviceConfigStoragePlan(schema string, tables []string) []string {
	owned := map[string]bool{}
	for _, table := range TenantOwned(tables) {
		owned[table] = true
	}
	if !owned["device_configs"] || !owned["entities"] {
		return nil
	}
	child, parent := quoteIdent(schema)+`."device_configs"`, quoteIdent(schema)+`."entities"`
	return []string{"ALTER TABLE " + child + ` ADD COLUMN IF NOT EXISTS entity_context_id uuid,
 ADD COLUMN IF NOT EXISTS device_entity_id uuid, ADD COLUMN IF NOT EXISTS binding_agent_id text,
 ADD COLUMN IF NOT EXISTS binding_source_ref text, ADD COLUMN IF NOT EXISTS binding_source_assigned_at timestamptz,
 ADD COLUMN IF NOT EXISTS binding_agent_assigned_at timestamptz, ADD COLUMN IF NOT EXISTS bound_at timestamptz`, fmt.Sprintf(`DO $config_shape$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname='device_configs_binding_complete') THEN
  ALTER TABLE %s ADD CONSTRAINT device_configs_binding_complete CHECK (
   (entity_context_id IS NULL AND device_entity_id IS NULL AND binding_agent_id IS NULL AND binding_source_ref IS NULL
    AND binding_source_assigned_at IS NULL AND binding_agent_assigned_at IS NULL AND bound_at IS NULL)
   OR (entity_context_id IS NOT NULL AND device_entity_id IS NOT NULL AND binding_agent_id IS NOT NULL AND binding_source_ref IS NOT NULL
    AND binding_source_assigned_at IS NOT NULL AND binding_agent_assigned_at IS NOT NULL AND bound_at IS NOT NULL
    AND octet_length(binding_agent_id) BETWEEN 1 AND 128 AND octet_length(binding_source_ref) BETWEEN 1 AND 1024
    AND bound_at>=binding_source_assigned_at AND bound_at>=binding_agent_assigned_at
    AND observed_at>=binding_source_assigned_at AND observed_at>=binding_agent_assigned_at AND observed_at<=bound_at)) NOT VALID;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=%s::regclass AND conname='device_configs_binding_device_fk') THEN
  ALTER TABLE %s ADD CONSTRAINT device_configs_binding_device_fk FOREIGN KEY(tenant_id,entity_context_id,device_entity_id)
   REFERENCES %s(tenant_id,context_id,id) ON DELETE CASCADE NOT VALID;
 END IF;
END $config_shape$`, quoteLiteral(child), child, quoteLiteral(child), child, parent)}
}
