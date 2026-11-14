// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type incidentVerdictRouteKey struct{ ContextID, RouterID, Address string }
type incidentVerdictRoute struct {
	Key    incidentVerdictRouteKey
	Route  *store.BGPRoutingLookup
	Digest string
}

// Query-start clocks and refreshable leases do not stand in for source content.
// Exact generation, ordered source sequence and every complete selected path do.
type incidentVerdictRouteFingerprint struct {
	Key      incidentVerdictRouteKey
	Source   *store.BGPRoutingSource
	View     store.BGPRoutingViewRef
	Prefix   netip.Prefix
	Paths    []store.BGPRoutingChange
	Sequence int64
}

func incidentVerdictRouteFingerprints(routes []incidentVerdictRoute) []incidentVerdictRouteFingerprint {
	out := make([]incidentVerdictRouteFingerprint, 0, len(routes))
	for _, item := range routes {
		value := incidentVerdictRouteFingerprint{Key: item.Key}
		if item.Route != nil {
			r := item.Route
			value.Source, value.View, value.Prefix, value.Paths, value.Sequence = &r.Source, r.View, r.Prefix, r.Paths, r.LastSequence
		}
		out = append(out, value)
	}
	return out
}

func (s *Server) loadIncidentVerdictRoutes(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, snapshot, original *incidentVerdictSnapshot, memory int64) error {
	keys := []incidentVerdictRouteKey{}
	if original != nil {
		for _, item := range original.routes {
			keys = append(keys, item.Key)
		}
	} else {
		seen := map[incidentVerdictRouteKey]bool{}
		for _, test := range snapshot.evidence.tests {
			for _, read := range test.reads {
				if !read.Available || read.ICMP == nil || (read.ICMP.Version != 2 && read.ICMP.Version != 3) {
					continue
				}
				for _, outcome := range read.ICMP.NetworkErrors {
					if err := ctx.Err(); err != nil {
						return err
					}
					if memory < 16 {
						return store.ErrIncidentImpactBudget
					}
					memory -= 16
					key := incidentVerdictRouteKey{ContextID: test.source.ContextID, RouterID: test.source.EntityID, Address: outcome.Responder}
					if !seen[key] {
						if memory < 4096 {
							return store.ErrIncidentImpactBudget
						}
						memory -= 4096
						seen[key] = true
						keys = append(keys, key)
					}
				}
			}
		}
	}
	snapshot.evidence.routes = map[incidentVerdictRouteKey]incidentVerdictRoute{}
	for _, key := range keys {
		if err := ctx.Err(); err != nil {
			return err
		}
		if memory < 4096 {
			return store.ErrIncidentImpactBudget
		}
		record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, key.ContextID)
		if err != nil {
			return err
		}
		resource := entityContextResource(record)
		resource["entity_id"] = key.RouterID
		if err := s.authorize(ctx, actor, entitySourcePermission(entity.BMPPeer), auth.RBACGlobal, resource); err != nil {
			return err
		}
		address, err := netip.ParseAddr(key.Address)
		if err != nil {
			return entity.ErrInvalidClaim
		}
		scope := entity.Scope{TenantID: sc.Tenant.String(), ContextID: key.ContextID}
		route, err := (store.BGPRouting{}).LookupRouterInScope(ctx, sc, scope, key.RouterID, address, store.BGPRoutingBudget{MemoryBytes: memory / 2, WorkUnits: memory / 2, StateBytes: memory / 2})
		item := incidentVerdictRoute{Key: key}
		switch {
		case err == nil:
			item.Route = &route
		case errors.Is(err, store.ErrBGPRoutingRouteMissing), errors.Is(err, store.ErrBGPRoutingSourceUnavailable), errors.Is(err, store.ErrBGPRoutingAmbiguousView):
			// Missing, ambiguous and stale views are unavailable, never a public
			// fallback relabelled as this incident's router-selected evidence.
		default:
			return err
		}
		encoded, err := json.Marshal(item)
		if err != nil {
			return err
		}
		cost := int64(4096) + 8*int64(len(encoded))
		if cost > memory {
			return store.ErrIncidentImpactBudget
		}
		memory -= cost
		fingerprint := incidentVerdictRouteFingerprints([]incidentVerdictRoute{item})
		digest, err := hashFlowRoleInputs(ctx, nil, fingerprint, cost)
		if err != nil {
			return err
		}
		item.Digest = hex.EncodeToString(digest)
		snapshot.routes = append(snapshot.routes, item)
		snapshot.evidence.routes[key] = item
	}
	return ctx.Err()
}
