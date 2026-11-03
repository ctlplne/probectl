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

// Related metadata follows only a current operator-owned exporter binding.
// The caller's raw flow agent ID is never read. Cache current facts once per
// typed owned subject inside the same RLS snapshot as its tag rules/revision.
func loadFlowTagSubjects(ctx context.Context, sc tenancy.Scope, snapshot *TenantTagSnapshot, wanted map[string]bool, maxBytes int64, charge func(...string) error) (map[string]map[string]string, error) {
	type subjectKey struct{ contextID, kind, id string }
	cache := map[subjectKey][]tags.Resolved{}
	addresses := make([]string, 0, len(snapshot.byAddress))
	for address := range snapshot.byAddress {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		addresses = append(addresses, address)
	}
	sort.Strings(addresses)
	result := map[string]map[string]string{}
	for _, address := range addresses {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		binding := snapshot.byAddress[address]
		values := map[string]string{}
		for _, kind := range []string{"device", "agent"} {
			if !wanted[kind] {
				continue
			}
			id := binding.deviceID
			if kind == "agent" {
				id = binding.agentID
			}
			ref, err := normalizeTagSubjectReference(TagSubjectReference{Kind: kind, ID: id})
			if err != nil {
				continue
			} // Legacy opaque agent names are not registered agent UUIDs.
			key := subjectKey{binding.contextID, kind, ref.ID}
			resolved, known := cache[key]
			if !known {
				if err := charge(key.contextID, key.kind, key.id); err != nil {
					return nil, err
				}
				scope := tags.Scope{TenantID: sc.Tenant.String(), ContextID: binding.contextID}
				subject, err := loadOwnedTagSubject(ctx, sc, scope, ref, maxBytes, charge)
				switch {
				case errors.Is(err, pgx.ErrNoRows), errors.Is(err, ErrTagSubjectFactsAmbiguous):
					cache[key] = nil
					continue // Withhold only unavailable metadata; never partial facts.
				case err != nil:
					return nil, err
				}
				contextSnapshot := snapshot.byContext[binding.contextID]
				if contextSnapshot == nil {
					return nil, ErrTagSnapshotUnavailable
				}
				resolved, err = contextSnapshot.ResolveContext(ctx, subject)
				if err != nil {
					return nil, err
				}
				cache[key] = resolved
			}
			for _, item := range resolved {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				lookup := kind + "." + item.Key
				if err := charge(address, lookup, item.Value); err != nil {
					return nil, err
				}
				values[lookup] = item.Value
			}
		}
		if len(values) > 0 {
			result[address] = values
		}
	}
	return result, nil
}
