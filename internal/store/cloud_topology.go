// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/topology"
)

const (
	maxCloudTopologySources = 8
	maxCloudTopologyBytes   = 1 << 20 // Bound before jsonb whitespace expansion.
	cloudTopologyFreshness  = time.Hour
)

type CloudTopologyInventories struct{}

// Save atomically replaces the latest complete observation for this source.
// The caller supplies a tenant transaction and appends its audit event in it.
func (CloudTopologyInventories) Save(ctx context.Context, sc tenancy.Scope, inventory topology.CloudInventory) error {
	inventory.ObservedAt = inventory.ObservedAt.UTC().Truncate(time.Microsecond)
	if err := inventory.Validate(); err != nil {
		return apierror.Validation("invalid cloud topology inventory").Wrap(err)
	}
	payload, err := json.Marshal(inventory)
	if err != nil || len(payload) > maxCloudTopologyBytes {
		return apierror.TooLarge("cloud topology inventory exceeds the storage budget")
	}
	tenant := sc.Tenant.String()
	if _, err := sc.Q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('cloud-topology:' || $1::text, 0))`, tenant); err != nil {
		return err
	}
	k := inventory.Source
	tag, err := sc.Q.Exec(ctx, `
		INSERT INTO cloud_topology_inventories (tenant_id, provider, account, location, observed_at, inventory)
		SELECT $1::uuid, $2, $3, $4, $5, $6::jsonb
		WHERE EXISTS (SELECT 1 FROM cloud_topology_inventories
			WHERE tenant_id=$1::uuid AND provider=$2 AND account=$3 AND location=$4)
		   OR (SELECT count(*) FROM cloud_topology_inventories WHERE tenant_id=$1::uuid) < $7
		ON CONFLICT (tenant_id, provider, account, location) DO UPDATE
		SET observed_at=EXCLUDED.observed_at, inventory=EXCLUDED.inventory
		WHERE cloud_topology_inventories.observed_at < EXCLUDED.observed_at`,
		tenant, k.Provider, k.Account, k.Location, inventory.ObservedAt, string(payload), maxCloudTopologySources)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return apierror.Conflict("cloud topology source limit or newer observation prevents replacement")
	}
	return nil
}

// Visible returns observations still fresh at the requested graph clock.
// Only each source's latest complete inventory is retained.
func (CloudTopologyInventories) Visible(ctx context.Context, sc tenancy.Scope, at time.Time) ([]topology.CloudInventory, error) {
	rows, err := sc.Q.Query(ctx, `SELECT provider, account, location, observed_at, inventory FROM cloud_topology_inventories
		WHERE tenant_id=$1::uuid AND observed_at > $2 AND observed_at <= $3
		ORDER BY provider, account, location LIMIT $4`, sc.Tenant.String(), at.Add(-cloudTopologyFreshness), at, maxCloudTopologySources+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	inventories := make([]topology.CloudInventory, 0)
	for rows.Next() {
		var key topology.CloudInventorySource
		var observed time.Time
		var payload []byte
		if err := rows.Scan(&key.Provider, &key.Account, &key.Location, &observed, &payload); err != nil {
			return nil, err
		}
		var inventory topology.CloudInventory
		if len(inventories) >= maxCloudTopologySources || json.Unmarshal(payload, &inventory) != nil || inventory.Source != key ||
			!inventory.ObservedAt.Equal(observed) || inventory.Validate() != nil {
			return nil, apierror.Unavailable("stored cloud topology inventory is invalid")
		}
		inventories = append(inventories, inventory)
	}
	return inventories, rows.Err()
}

func (CloudTopologyInventories) PruneBefore(ctx context.Context, sc tenancy.Scope, cutoff time.Time) (int64, error) {
	tag, err := sc.Q.Exec(ctx, `DELETE FROM cloud_topology_inventories WHERE tenant_id=$1::uuid AND observed_at < $2`, sc.Tenant.String(), cutoff)
	return tag.RowsAffected(), err
}
