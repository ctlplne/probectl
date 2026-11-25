// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/netip"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func (s *Server) exportIncidentCarrier(ctx context.Context, actor *auth.Principal, inc *incident.Incident, input incident.CarrierInput, publication *incidentEvidenceFinalizer) (*incident.CarrierPack, error) {
	if publication != nil {
		*publication = nil
	}
	if actor == nil || actor.UserID == "" || inc == nil || inc.TenantID != actor.TenantID {
		return nil, apierror.Forbidden("carrier export requires a current tenant user")
	}
	if input.From.IsZero() || !input.To.After(input.From) || input.To.After(time.Now().UTC()) {
		return nil, apierror.Validation("explicit past carrier from/to are required")
	}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, incidentImpactExportKey{}, true)
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	if budget.Validate() != nil {
		return nil, apierror.Unavailable("carrier source admission is unavailable")
	}
	// Retained original source snapshots, output and final rechecks share one
	// captured operation budget. No member, row or time window is truncated.
	memory := budget.MemoryBytes / 3
	snapshot, err := s.loadIncidentVerdictSnapshot(ctx, actor, inc.ID, input.From.Truncate(time.Microsecond), input.To, memory, nil)
	if err != nil {
		return nil, err
	}
	if err := requireImpactIncidentHeader(actor.TenantID, inc, snapshot.inputs); err != nil {
		return nil, err
	}
	// The index read includes the boundary bucket. Project exact source clocks
	// against the caller's actual window, preserving legacy ambiguity.
	projection := snapshot
	projection.evidence.from = input.From
	result, err := projectIncidentCarrier(ctx, actor.TenantID, inc.ID, input.From, input.To, projection, budget.MemoryBytes/6)
	if err != nil {
		return nil, err
	}
	routes, err := s.carrierRoutingSnapshot(ctx, actor, snapshot, carrierAffectedPrefixes(inc, snapshot), input.From, input.To, memory/3, nil)
	if err != nil {
		return nil, err
	}
	for _, event := range routes {
		result.Routing = append(result.Routing, change.Event{ID: event.ID, Source: event.Source, Kind: event.Kind, Prefix: event.Prefix, Target: event.Routing.RouterID, Ref: event.ID, OccurredAt: event.OccurredAt, ReceivedAt: event.ReceivedAt, Routing: event.Routing})
	}
	if len(result.Routing) > 0 {
		result.Coverage.Routing = "observed_original_changes"
	} else {
		result.Coverage.Missing = append(result.Coverage.Missing, "retained_affected_prefix_routing_changes")
	}
	counters, err := s.loadCarrierCounters(ctx, actor, snapshot, &result, budget)
	if err != nil {
		return nil, err
	}
	result.Summary = carrierSummary(result)
	redacted, err := redactIncidentCarrier(result, s.incidentEvidenceRedaction(ctx), actor.TenantID)
	if err != nil {
		return nil, err
	}
	validate := func(ctx context.Context) error {
		ctx = context.WithValue(ctx, incidentImpactExportKey{}, true)
		after, err := s.loadIncidentVerdictSnapshot(ctx, actor, inc.ID, input.From.Truncate(time.Microsecond), input.To, memory, &snapshot)
		if err != nil {
			return err
		}
		if snapshot.digest != after.digest {
			return apierror.Unavailable("carrier incident membership or source authority changed; retry")
		}
		if err := requireImpactIncidentHeader(actor.TenantID, inc, after.inputs); err != nil {
			return err
		}
		if err := incidentVerdictSnapshotStillCurrent(after, &incident.FaultVerdict{}); err != nil {
			return err
		}
		if _, err := s.carrierRoutingSnapshot(ctx, actor, after, nil, input.From, input.To, memory/3, routes); err != nil {
			return err
		}
		for _, check := range counters {
			if _, err := s.capacityCounterSnapshot(ctx, actor, check.selected, &check.target, check.rows, check.budget); err != nil {
				return err
			}
		}
		return ctx.Err()
	}
	if err := validate(ctx); err != nil {
		return nil, err
	}
	if publication != nil {
		*publication = validate
	}
	return &redacted, nil
}

func carrierAffectedPrefixes(inc *incident.Incident, snapshot incidentVerdictSnapshot) []netip.Prefix {
	out := []netip.Prefix{}
	seen := map[netip.Prefix]bool{}
	add := func(text string) {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			if address, e := netip.ParseAddr(text); e == nil {
				prefix = netip.PrefixFrom(address, address.BitLen())
			} else {
				return
			}
		}
		prefix = prefix.Masked()
		if !seen[prefix] {
			seen[prefix] = true
			out = append(out, prefix)
		}
	}
	add(inc.Prefix)
	// A free-form incident target cannot introduce a source. Configured tests
	// were selected through canonical incident membership in the tenant store.
	for _, test := range snapshot.tests {
		add(test.Target)
	}
	for _, group := range snapshot.pathGroups {
		for _, round := range group.Rounds {
			add(round.Path.TargetIP)
		}
	}
	return out
}

func (s *Server) carrierRoutingSnapshot(ctx context.Context, actor *auth.Principal, snapshot incidentVerdictSnapshot, prefixes []netip.Prefix, from, to time.Time, memory int64, originals []change.Event) ([]change.Event, error) {
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return nil, err
	}
	var out []change.Event
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, principal, permChangeRead, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: actor.TenantID, "incident_id": snapshot.inputs.IncidentID}); err != nil {
			return err
		}
		authorize := s.routingChangeAuthorizer(principal, permChangeRead, permIncidentRead, permAIQuery)
		if originals != nil {
			return (store.ChangeEvents{}).VerifyRoutingChangeReferencesInScope(ctx, sc, originals, memory, authorize)
		}
		members, err := carrierRoutingMembers(actor.TenantID, snapshot, memory)
		if err != nil {
			return err
		}
		out, err = (store.ChangeEvents{}).IncidentRoutingChangesInScope(ctx, sc, members, prefixes, from, to, memory, authorize)
		return err
	})
	return out, err
}

// Rows and their current source references are retained only for this operation.
// Original receipt witnesses, user grants and source lifecycle are rechecked
// after packaging; no cached actor or signed bytes grant future online access.
type incidentCarrierCounterCheck struct {
	selected capacityCounterSelection
	target   store.DeviceCounterInterface
	rows     []flowstore.CounterRow
	budget   flowstore.CounterBudget
}

// An incident on an interface selects its current canonical router parent,
// never another router that happens to share an address or display label.
// Original source verification still authorizes each selected router/prefix.
func carrierRoutingMembers(tenant string, snapshot incidentVerdictSnapshot, memory int64) (*store.IncidentImpactInputs, error) {
	if snapshot.inputs == nil || snapshot.inputs.TenantID != tenant {
		return nil, apierror.Forbidden("current carrier membership is required")
	}
	if memory < 4096 || int64(len(snapshot.inputs.Entities))+int64(len(snapshot.evidence.interfaces)) > memory/1024 {
		return nil, store.ErrIncidentImpactBudget
	}
	selected := *snapshot.inputs
	selected.Entities = append([]store.IncidentImpactEntity{}, snapshot.inputs.Entities...)
	seen := map[[2]string]bool{}
	for _, member := range selected.Entities {
		seen[[2]string{member.ContextID, member.EntityID}] = true
	}
	for _, item := range snapshot.evidence.interfaces {
		if !item.direct || !item.source.Current {
			continue
		}
		source := item.source
		if source.TenantID != tenant || source.ContextID == "" || source.RouterID == "" {
			return nil, apierror.Forbidden("carrier interface parent scope is unavailable")
		}
		key := [2]string{source.ContextID, source.RouterID}
		if seen[key] {
			continue
		}
		seen[key] = true
		selected.Entities = append(selected.Entities, store.IncidentImpactEntity{ContextID: source.ContextID, EntityID: source.RouterID, SignalIDs: []string{}})
	}
	return &selected, nil
}
