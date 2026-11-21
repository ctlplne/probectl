// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type bgpRPKIPathPosture struct {
	RouterID       string                `json:"router_id"`
	Vantage        string                `json:"vantage"`
	Generation     string                `json:"generation"`
	ViewObservedAt time.Time             `json:"view_observed_at"`
	Origin         *uint32               `json:"origin_asn,omitempty"`
	PathID         uint32                `json:"path_id"`
	HasPathID      bool                  `json:"has_path_id"`
	RPKI           opendata.RPKIPosture  `json:"rpki"`
	IRR            []opendata.IRRPosture `json:"irr,omitempty"`
	RelatedHijacks []store.BGPRPKIHijack `json:"related_hijacks,omitempty"`
}

type bgpRPKITrendPoint struct {
	ID         string    `json:"id"`
	ObservedAt time.Time `json:"observed_at"`
	Vantage    string    `json:"vantage"`
	store.BGPRPKIHistoryObservation
}

type bgpRPKICurrentPosture struct {
	ContextID string               `json:"context_id"`
	PrefixID  string               `json:"prefix_id"`
	MonitorID string               `json:"monitor_id"`
	Prefix    netip.Prefix         `json:"prefix"`
	AsOf      time.Time            `json:"as_of"`
	Coverage  string               `json:"coverage"`
	Paths     []bgpRPKIPathPosture `json:"paths"`
	Trend     []bgpRPKITrendPoint  `json:"trend"`
}

// readBGPRPKICurrentInScope uses retained history to identify authorized
// sources. Every displayed path comes from the still-current, complete view.
func (s *Server) readBGPRPKICurrentInScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal,
	target bgpRPKIPostureTarget, intendedOrigin uint32, from, at time.Time, limit int, budget store.BGPRoutingBudget) (bgpRPKICurrentPosture, error) {
	var empty bgpRPKICurrentPosture
	if target.Context.TenantID != sc.Tenant.String() || target.Prefix.Scope.TenantID != sc.Tenant.String() {
		return empty, tenancy.ErrNoTenant
	}
	query := store.BGPASPathHistorySelection{Monitor: target.Monitor.ID, ContextID: target.Context.ContextID, SourceKind: "router_bmp",
		From: from, To: at, Limit: limit, IncludeRPKI: true}
	records, partial, err := store.BGPASPathHistoryInScope(ctx, sc, query, budget)
	if err != nil {
		return empty, err
	}
	seen := make(map[string]bool)
	authorized := s.routingChangeAuthorizer(actor)
	snapshot := s.openDataEnricher.RPKI(at)
	registry := s.openDataEnricher.IRR()
	// A bounded history page also bounds how much work any one source can
	// account for, including copied validator assertions.
	sourceCount := int64(max(1, len(records)))
	sourceBudget := store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / sourceCount,
		WorkUnits: budget.WorkUnits / sourceCount, StateBytes: budget.StateBytes}
	out := bgpRPKICurrentPosture{ContextID: target.Context.ContextID, PrefixID: target.Prefix.ID, MonitorID: target.Monitor.ID,
		Prefix: target.Monitor.Prefix, AsOf: at, Coverage: "no_retained_sources", Paths: []bgpRPKIPathPosture{}, Trend: []bgpRPKITrendPoint{}}
	for _, original := range records {
		if len(original.Current) != 0 {
			point, err := store.ReadBGPRPKIHistoryInScope(ctx, sc, target.Monitor.Prefix, original, sourceBudget, authorized)
			switch {
			case errors.Is(err, store.ErrBGPRoutingSourceUnavailable):
				partial = true
			case err != nil:
				return empty, err
			default:
				out.Trend = append(out.Trend, bgpRPKITrendPoint{ID: original.ID, ObservedAt: original.ObservedAt,
					Vantage: original.Vantage, BGPRPKIHistoryObservation: point})
			}
		}
		if seen[original.Vantage] {
			continue
		}
		seen[original.Vantage] = true
		paths, available, err := evaluateBGPRPKILiveSource(ctx, sc, target.Monitor.Prefix, original, snapshot, registry, at, intendedOrigin, sourceBudget, authorized)
		if err != nil {
			return empty, err
		}
		partial = partial || !available
		if int64(len(paths)) > budget.MemoryBytes/1024-int64(len(out.Paths)) {
			return empty, store.ErrBGPRoutingBudget
		}
		if err := s.linkBGPRPKIHijacks(ctx, sc, actor, target, original.ObservedAt, paths); err != nil {
			return empty, err
		}
		out.Paths = append(out.Paths, paths...)
	}
	switch {
	case partial:
		out.Coverage = "incomplete_source_population"
		for i := range out.Paths {
			out.Paths[i].RPKI.Suggestion = nil
		}
	case len(records) != 0:
		out.Coverage = "observed_source_population"
	}
	return out, ctx.Err()
}

func evaluateBGPRPKILiveSource(ctx context.Context, sc tenancy.Scope, prefix netip.Prefix, original store.BGPASPathHistoryRecord,
	snapshot opendata.RPKISnapshot, registry *opendata.IRRIndex, at time.Time, intendedOrigin uint32, budget store.BGPRoutingBudget,
	authorize store.RoutingChangeAuthorizer) ([]bgpRPKIPathPosture, bool, error) {
	readBudget := store.BGPRoutingBudget{MemoryBytes: budget.MemoryBytes / 2, WorkUnits: budget.WorkUnits / 2, StateBytes: budget.StateBytes}
	lookup, err := store.CurrentBGPRPKIPrefixInScope(ctx, sc, prefix, original, readBudget, authorize)
	switch {
	case errors.Is(err, store.ErrBGPRoutingRouteMissing):
		return nil, true, nil
	case errors.Is(err, store.ErrBGPRoutingSourceUnavailable):
		return nil, false, nil
	case err != nil:
		return nil, false, err
	}
	pathCount := int64(max(1, len(lookup.Paths)))
	results := make([]bgpRPKIPathPosture, 0, len(lookup.Paths))
	for i, path := range lookup.Paths {
		origin := lookup.PathFields[i].OriginAS
		suggest := origin != nil && intendedOrigin == *origin && intendedOrigin != 0
		verdict, err := opendata.AssessRPKIPosture(ctx, snapshot, at, prefix, origin, suggest, readBudget.MemoryBytes/pathCount, readBudget.WorkUnits/pathCount)
		if err != nil {
			return nil, false, err
		}
		registration, err := registry.Assess(ctx, prefix, origin, at, budget.MemoryBytes/(8*pathCount))
		if err != nil {
			return nil, false, err
		}
		results = append(results, bgpRPKIPathPosture{RouterID: original.RouterID, Vantage: original.Vantage,
			Generation: lookup.View.Generation, ViewObservedAt: lookup.LastObservedAt, Origin: origin,
			PathID: path.PathID, HasPathID: path.HasPathID, RPKI: verdict, IRR: registration})
	}
	return results, true, nil
}

func (s *Server) linkBGPRPKIHijacks(ctx context.Context, sc tenancy.Scope, actor *auth.Principal,
	target bgpRPKIPostureTarget, observed time.Time, paths []bgpRPKIPathPosture) error {
	if actor == nil || !actor.Has(permIncidentRead) {
		return nil
	}
	links := make(map[uint32][]store.BGPRPKIHijack)
	resource := entityContextResource(target.Context)
	resource["prefix"], resource["entity_id"] = target.Monitor.Prefix.String(), target.Prefix.ID
	const drift = time.Minute
	for i := range paths {
		path := &paths[i]
		if path.Origin == nil || path.RPKI.Status != "invalid" {
			continue
		}
		origin := *path.Origin
		if prior, checked := links[origin]; checked {
			path.RelatedHijacks = prior
			continue
		}
		candidates, err := store.BGPRPKIHijacksInScope(ctx, sc, target.Context.ContextID, target.Monitor.Prefix, origin,
			observed.Add(-drift), observed.Add(drift))
		if err != nil {
			return err
		}
		for _, candidate := range candidates {
			resource["incident_id"] = candidate.IncidentID
			if err := s.authorize(ctx, actor, permIncidentRead, auth.RBACGlobal, resource); err == nil {
				path.RelatedHijacks = append(path.RelatedHijacks, candidate)
			}
		}
		links[origin] = path.RelatedHijacks
	}
	return ctx.Err()
}
