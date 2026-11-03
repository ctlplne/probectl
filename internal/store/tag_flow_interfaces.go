// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"sort"

	"github.com/jackc/pgx/v5"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Resolve once per owned device, never from an index/agent supplied as an
// ownership hint. All candidate entities and current evidence share the tag
// snapshot transaction. The latest complete poll is also a negative fence.
func loadFlowTagInterfaces(ctx context.Context, sc tenancy.Scope, snapshot *TenantTagSnapshot, maxBytes int64, charge func(...string) error) (map[string]map[uint32]map[string]string, error) {
	type deviceKey struct{ contextID, id string }
	cache := map[deviceKey]map[uint32]map[string]string{}
	result := map[string]map[uint32]map[string]string{}
	addresses := make([]string, 0, len(snapshot.byAddress))
	for address := range snapshot.byAddress {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	for _, address := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		binding := snapshot.byAddress[address]
		if binding.deviceID == "" {
			continue
		}
		key := deviceKey{binding.contextID, binding.deviceID}
		values, loaded := cache[key]
		if !loaded {
			if err := charge(key.contextID, key.id); err != nil {
				return nil, err
			}
			var err error
			values, err = loadFlowTagDeviceInterfaces(ctx, sc, snapshot, key.contextID, key.id, maxBytes, charge)
			if err != nil {
				return nil, err
			}
			cache[key] = values
		}
		// This shares immutable values only inside this private snapshot. Public
		// backend projections copy and charge every exporter/index/key/value.
		result[address] = values
	}
	return result, nil
}

func loadFlowTagDeviceInterfaces(ctx context.Context, sc tenancy.Scope, snapshot *TenantTagSnapshot, contextID, deviceID string, maxBytes int64, charge func(...string) error) (map[uint32]map[string]string, error) {
	limit := maxBytes/2048 + 1
	rows, err := sc.Q.Query(ctx, `SELECT id::text,label,interface_index FROM entities
        WHERE tenant_id=$1 AND context_id=$2 AND kind='interface' AND parent_entity_id=$3
        AND interface_index>0 AND EXISTS(SELECT 1 FROM entities device
        WHERE device.tenant_id=$1 AND device.context_id=$2 AND device.id=$3 AND device.kind='device')
        ORDER BY interface_index,id LIMIT $4`, sc.Tenant.String(), contextID, deviceID, limit)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		id, label string
		index     uint32
	}
	var candidates []candidate
	for rows.Next() {
		if int64(len(candidates))+1 >= limit {
			rows.Close()
			return nil, ErrTagSnapshotBudget
		}
		var item candidate
		if err := rows.Scan(&item.id, &item.label, &item.index); err != nil {
			rows.Close()
			return nil, err
		}
		if err := charge(item.id, item.label); err != nil {
			rows.Close()
			return nil, err
		}
		candidates = append(candidates, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	compiled := snapshot.byContext[contextID]
	if compiled == nil {
		return nil, ErrTagSnapshotUnavailable
	}
	values := map[uint32]map[string]string{}
	owners := map[uint32]int{}
	for _, item := range candidates {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		subject := tags.Subject{Scope: tags.Scope{TenantID: sc.Tenant.String(), ContextID: contextID}, Kind: "interface", ID: item.id, Name: item.label, AddressSide: "interface"}
		err := loadCurrentTagEntityFacts(ctx, sc, &subject, deviceID, maxBytes, charge, item.index)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			continue
		case errors.Is(err, ErrTagSubjectFactsAmbiguous):
			owners[item.index] = 2
			delete(values, item.index)
			continue
		case err != nil:
			return nil, err
		}
		owners[item.index]++
		if owners[item.index] > 1 {
			delete(values, item.index)
			continue // A second current ID makes the index ambiguous, even without tags.
		}
		resolved, err := compiled.ResolveContext(ctx, subject)
		if err != nil {
			return nil, err
		}
		entries := map[string]string{}
		for _, tag := range resolved {
			if err := charge(tag.Key, tag.Value); err != nil {
				return nil, err
			}
			entries[tag.Key] = tag.Value
		}
		if len(entries) > 0 {
			values[item.index] = entries
		}
	}
	return values, nil
}
