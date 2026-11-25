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

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testspec"
)

type routingTransferProbePlan struct {
	target     netip.Addr
	tests      [2]store.IncidentConfiguredTest
	bindings   [2]testspec.RoutingProbeBinding
	validUntil time.Time
}

func (s *Server) routingTransferProbePlanInScope(ctx context.Context, sc tenancy.Scope, op capacityAgreementOperation,
	scope entity.Scope, record entity.ContextRecord, authorize topologyFailureAuthorize, ports routingTransferPorts,
	route routingTransferRoute, requested [2]store.RoutingProbeTest) (routingTransferProbePlan, error) {
	var out routingTransferProbePlan
	handoffs := [2]store.DeviceCounterInterface{ports.source, ports.candidate}
	peers := [2]netip.Addr{route.selected, route.candidate}
	principal := auth.PrincipalFrom(ctx)
	if record.TenantID != scope.TenantID || record.ContextID != scope.ContextID || op.actor == nil || principal == nil ||
		principal.TenantID != op.actor.TenantID || principal.UserID != op.actor.UserID ||
		op.actor.TenantID != scope.TenantID || handoffs[0].Scope != scope || handoffs[1].Scope != scope ||
		handoffs[0].Source.DeviceID == "" || handoffs[0].Source.DeviceID != handoffs[1].Source.DeviceID ||
		handoffs[0].InterfaceID == handoffs[1].InterfaceID || peers[0] == peers[1] {
		return out, entity.ErrScopeMismatch
	}
	reader := store.NewEntityRegistry(s.pool)
	tests, err := reader.RoutingProbeTestsInScope(ctx, sc, scope, handoffs[0].Source.DeviceID, requested,
		op.budget.MemoryBytes/8, s.routingTransferProbeAuthorizer(principal, requested, authorize))
	if errors.Is(err, store.ErrIncidentImpactBudget) {
		return out, flowstore.ErrExplorerBudget
	}
	if err != nil {
		return out, err
	}
	out.tests, out.validUntil = tests, route.validUntil
	counters := store.NewDeviceCounterCaptures(s.pool)
	for i, probe := range tests {
		if err := authorize(ctx, record, handoffs[i].InterfaceID); err != nil {
			return routingTransferProbePlan{}, err
		}
		current, err := counters.CurrentInterfaceInScope(ctx, sc, scope, handoffs[i].InterfaceID)
		if err != nil {
			return routingTransferProbePlan{}, err
		}
		if !sameCapacityCounterInterface(handoffs[i], current) ||
			probe.SourceGeneration != current.Generation || probe.PathBinding.Scope != scope ||
			probe.PathBinding.Target != probe.Target || probe.CurrentSince.IsZero() {
			return routingTransferProbePlan{}, entity.ErrScopeMismatch
		}
		expected, err := testspec.ParseRoutingProbeBinding(probe.Type, probe.Target, probe.Definition.Params)
		if err != nil || expected == nil || expected.HandoffID != handoffs[i].InterfaceID || expected.Peer != peers[i] {
			return routingTransferProbePlan{}, entity.ErrScopeMismatch
		}
		target, err := netip.ParseAddr(probe.Target)
		if err != nil || !route.prefix.Contains(target) || i > 0 && out.target != target {
			return routingTransferProbePlan{}, apierror.Validation("both routing probes must use the same literal destination inside the exact prefix")
		}
		out.target, out.bindings[i] = target, *expected
		out.validUntil = earlierRoutingProbeDeadline(out.validUntil, current.ValidUntil)
		out.validUntil = earlierRoutingProbeDeadline(out.validUntil, *probe.MeasurementIdentityUntil)
		if probe.ValidUntil != nil {
			out.validUntil = earlierRoutingProbeDeadline(out.validUntil, *probe.ValidUntil)
		}
	}
	if !out.validUntil.After(time.Now()) {
		return routingTransferProbePlan{}, apierror.Unavailable("the routing probe, handoff or route has expired")
	}
	return out, ctx.Err()
}

func (s *Server) routingTransferProbeAuthorizer(actor *auth.Principal, requested [2]store.RoutingProbeTest,
	authorize topologyFailureAuthorize) func(context.Context, entity.ContextRecord, store.IncidentImpactEntity, string) error {
	return func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, testID string) error {
		if err := authorize(ctx, record, member.EntityID); err != nil || testID == "" {
			return err
		}
		for _, key := range requested {
			if key.TestID != testID {
				continue
			}
			resource := entityContextResource(record)
			resource["entity_id"], resource["test_id"], resource["agent_id"] = member.EntityID, key.TestID, key.AgentID
			if err := s.authorize(ctx, actor, permTestRead, auth.RBACGlobal, resource); err != nil {
				return err
			}
			return s.authorize(ctx, actor, permAgentRead, auth.RBACGlobal, resource)
		}
		return entity.ErrScopeMismatch
	}
}

func earlierRoutingProbeDeadline(current, bound time.Time) time.Time {
	if bound.Before(current) {
		return bound
	}
	return current
}
