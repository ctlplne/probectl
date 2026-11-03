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

// SetEntityNetworkPrefix preserves the canonical ID and all assignments.
// The caller authorizes the current context and appends audit in this same
// tenant transaction. RLS and the typed predicate also reject foreign kinds.
func (s *EntityRegistry) SetEntityNetworkPrefix(ctx context.Context, sc tenancy.Scope, contextID, id, raw string) (entity.Record, error) {
	if s == nil || s.pool == nil {
		return entity.Record{}, ErrEntityRegistryUnavailable
	}
	contextID, err := validRegistryUUID(contextID)
	if err != nil {
		return entity.Record{}, err
	}
	id, err = validRegistryUUID(id)
	if err != nil {
		return entity.Record{}, err
	}
	network, err := entity.NormalizeNetworkPrefix(entity.Prefix, raw)
	if err != nil {
		return entity.Record{}, err
	}
	record := entity.Record{Scope: entity.Scope{TenantID: sc.Tenant.String(), ContextID: contextID}, ID: id, Kind: entity.Prefix}
	err = sc.Q.QueryRow(ctx, `UPDATE entities SET network_prefix=NULLIF($4,'')::cidr,
		updated_at=CASE WHEN network_prefix IS DISTINCT FROM NULLIF($4,'')::cidr THEN clock_timestamp() ELSE updated_at END
		WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND kind='prefix'
		RETURNING label,COALESCE(network_prefix::text,''),created_at,updated_at`,
		sc.Tenant.String(), contextID, id, network).Scan(&record.Label, &record.NetworkPrefix, &record.CreatedAt, &record.UpdatedAt)
	return record, err
}
