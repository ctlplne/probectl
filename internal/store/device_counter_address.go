// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// CurrentAddressInterface resolves the original interface-address observation,
// not the address resolver's parent-device projection. A device match alone
// cannot select its port. Two distinct current ports remain ambiguous.
func (s *DeviceCounterCaptures) CurrentAddressInterface(ctx context.Context, scope entity.Scope, deviceID, address string) (string, error) {
	want, err := scope.Normalize()
	bound, ok := tenancy.FromContext(ctx)
	if err != nil || !ok || bound.String() != want.TenantID {
		return "", entity.ErrScopeMismatch
	}
	alias, err := (entity.AliasKey{Kind: entity.AddressAlias, Value: address}).Normalize()
	if err != nil {
		return "", err
	}
	id := ""
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT DISTINCT node.id::text
 FROM entity_evidence e
 JOIN entities node ON (node.tenant_id,node.context_id,node.id)=(e.tenant_id,e.context_id,e.entity_id)
 WHERE e.tenant_id=$1 AND e.context_id=$2 AND node.kind='interface' AND node.parent_entity_id=$3
   AND e.alias_kind='address' AND e.alias_value=$4 AND e.source_kind='device_target'
   AND (node.source_agent_id,node.configured_ref)=(e.agent_id,e.configured_ref)
   AND `+currentEntityEvidenceSQL(false)+` LIMIT 2`, want.TenantID, want.ContextID, deviceID, alias.Value)
		if err != nil {
			return err
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			if err := rows.Scan(&id); err != nil {
				return err
			}
			count++
		}
		if count != 1 {
			id = ""
		}
		return rows.Err()
	})
	return id, err
}
