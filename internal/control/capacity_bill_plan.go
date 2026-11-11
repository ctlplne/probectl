// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"slices"
	"strconv"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type capacityBillMemberKey struct{ context, iface string }
type capacityBillParameters struct {
	at     time.Time
	gap    time.Duration
	bounds map[capacityBillMemberKey]uint64
}
type capacityBillMemberPlan struct {
	target  store.DeviceCounterInterface
	maximum uint64
}
type capacityBillPlan struct {
	agreement flow.CapacityAgreement
	period    flow.CapacityBillingPeriod
	circuit   *store.CapacityCircuitSnapshot
	members   []capacityBillMemberPlan
	asOf      time.Time
}

func capacityBillInput(input flow.CapacityBillRequest, memoryBytes int64) (capacityBillParameters, error) {
	none := capacityBillParameters{}
	version, err := strconv.ParseInt(input.Version, 10, 64)
	if err != nil || version <= 0 || strconv.FormatInt(version, 10) != input.Version {
		return none, apierror.Validation("an exact recorded agreement revision is required")
	}
	at, err := time.Parse(time.RFC3339Nano, input.At)
	if err != nil {
		return none, apierror.Validation("an RFC3339 instant selecting the billing period is required")
	}
	gap, err := time.ParseDuration(input.MaximumPollGap)
	if err != nil || gap <= 0 {
		return none, apierror.Validation("a positive maximum counter poll gap is required")
	}
	if memoryBytes <= 0 || int64(len(input.PhysicalBounds)) > memoryBytes/4096 {
		return none, apierror.TooLarge("complete physical assumptions exceed resource admission")
	}
	parameters := capacityBillParameters{at: at, gap: gap, bounds: make(map[capacityBillMemberKey]uint64, len(input.PhysicalBounds))}
	for _, bound := range input.PhysicalBounds {
		for _, id := range []string{bound.ContextID, bound.InterfaceID} {
			parsed, err := gouuid.Parse(id)
			if err != nil || parsed == gouuid.Nil || parsed.String() != id {
				return none, apierror.Validation("physical assumptions require canonical context and interface identities")
			}
		}
		maximum, err := strconv.ParseUint(bound.MaxBPS, 10, 64)
		key := capacityBillMemberKey{bound.ContextID, bound.InterfaceID}
		if err != nil || maximum == 0 || strconv.FormatUint(maximum, 10) != bound.MaxBPS || parameters.bounds[key] != 0 {
			return none, apierror.Validation("one positive exact physical upper bound per member is required")
		}
		parameters.bounds[key] = maximum
	}
	return parameters, nil
}

func (s *Server) capacityBillSnapshot(ctx context.Context, op capacityAgreementOperation, id string, input flow.CapacityBillRequest, parameters capacityBillParameters, previous *capacityBillPlan, rows []flowstore.CounterRow) (capacityBillPlan, error) {
	none := capacityBillPlan{}
	ctx, err := bindFlowRoleContext(ctx, op.actor)
	if err != nil {
		return none, err
	}
	if err := s.currentCapacityAgreementActor(ctx, op.actor, false); err != nil {
		return none, err
	}
	var result capacityBillPlan
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, op.actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, op.actor)
		if err != nil {
			return err
		}
		result, err = s.capacityBillPlanInScope(ctx, sc, op, principal, id, input, parameters)
		if err != nil {
			return err
		}
		if previous != nil && !sameCapacityBillPlan(*previous, result) {
			return apierror.Unavailable("capacity terms, membership or source authority changed; retry")
		}
		return validateCapacityBillRows(ctx, sc, store.NewDeviceCounterCaptures(s.pool), result, rows, op.budget.MemoryBytes/8)
	})
	if err != nil {
		return none, err
	}
	return result, nil
}

func (s *Server) capacityBillPlanInScope(ctx context.Context, sc tenancy.Scope, op capacityAgreementOperation, principal *auth.Principal, id string, input flow.CapacityBillRequest, parameters capacityBillParameters) (capacityBillPlan, error) {
	none := capacityBillPlan{}
	agreement, err := op.store.CapacityAgreementInScope(ctx, sc, op.actor.UserID, id, input.Version, nil)
	if err != nil {
		return none, err
	}
	if !agreement.TargetPresent {
		return none, apierror.Unavailable("the recorded target has retired; measured billing is unavailable")
	}
	period, err := flow.CapacityBillingPeriodAt(ctx, agreement.Definition, parameters.at, op.budget.MemoryBytes/8, op.budget.ReadBytes/8)
	if err != nil {
		return none, err
	}
	for _, at := range []time.Time{period.From, period.To.Add(-time.Nanosecond)} {
		terms, err := op.store.CapacityAgreementInScope(ctx, sc, op.actor.UserID, id, "", &at)
		if err != nil {
			return none, err
		}
		if terms.Version != agreement.Version {
			return none, apierror.Validation("the selected recorded terms must cover the complete billing period")
		}
	}
	authorize := func(ctx context.Context, record entity.ContextRecord) error {
		if record.TenantID != principal.TenantID {
			return entity.ErrScopeMismatch
		}
		for _, permission := range []string{ai.PermEntitiesRead, ai.PermMetricsRead} {
			if err := s.authorize(ctx, principal, permission, auth.RBACGlobal, entityContextResource(record)); err != nil {
				return err
			}
		}
		return nil
	}
	plan := capacityBillPlan{agreement: agreement, period: period, members: []capacityBillMemberPlan{}}
	members, circuit, err := s.capacityBillMembersInScope(ctx, sc, principal, agreement.Definition.Target, op.budget.MemoryBytes/16, authorize)
	if err != nil {
		return none, err
	}
	plan.circuit = circuit
	if int64(len(members)) > op.budget.MemoryBytes/(32*4096) {
		return none, apierror.TooLarge("complete capacity members exceed resource admission")
	}
	if len(members) == 0 || len(members) != len(parameters.bounds) {
		return none, apierror.Validation("physical upper bounds must cover the complete current member set")
	}
	reader := store.NewDeviceCounterCaptures(s.pool)
	for _, member := range members {
		maximum := parameters.bounds[capacityBillMemberKey{member.Scope.ContextID, member.InterfaceID}]
		if maximum == 0 {
			return none, apierror.Validation("physical upper bounds must cover the complete current member set")
		}
		target, err := reader.CurrentInterfaceInScope(ctx, sc, member.Scope, member.InterfaceID)
		if err != nil {
			return none, err
		}
		plan.members = append(plan.members, capacityBillMemberPlan{target: target, maximum: maximum})
	}
	if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&plan.asOf); err != nil {
		return none, err
	}
	return plan, nil
}

func (s *Server) capacityBillMembersInScope(ctx context.Context, sc tenancy.Scope, principal *auth.Principal, target flow.CapacityTarget, memoryBytes int64, authorize func(context.Context, entity.ContextRecord) error) ([]store.CapacityCircuitMember, *store.CapacityCircuitSnapshot, error) {
	if target.Kind == "interface" {
		record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, target.ContextID)
		if err != nil {
			return nil, nil, err
		}
		if err := authorize(ctx, record); err != nil {
			return nil, nil, err
		}
		return []store.CapacityCircuitMember{{Scope: entity.Scope{TenantID: principal.TenantID, ContextID: target.ContextID}, InterfaceID: target.InterfaceID}}, nil, nil
	}
	if target.Kind != "circuit" {
		return nil, nil, apierror.Validation("a canonical interface or circuit target is required")
	}
	if err := s.authorize(ctx, principal, permTagsRead, auth.RBACGlobal, map[string]string{auth.ResourceTenantKey: principal.TenantID}); err != nil {
		return nil, nil, err
	}
	circuit, err := store.NewTagSnapshots(s.pool).CapacityCircuitInScope(ctx, sc, target.TagID, target.TagValue, memoryBytes, func(ctx context.Context, record entity.ContextRecord) error {
		if err := s.authorize(ctx, principal, permTagsRead, auth.RBACGlobal, entityContextResource(record)); err != nil {
			return err
		}
		return authorize(ctx, record)
	})
	if err != nil {
		return nil, nil, err
	}
	return circuit.Members, &circuit, nil
}

func sameCapacityBillPlan(a, b capacityBillPlan) bool {
	if a.agreement.ID != b.agreement.ID || a.agreement.TenantID != b.agreement.TenantID || a.agreement.Version != b.agreement.Version ||
		a.agreement.CurrentVersion != b.agreement.CurrentVersion || a.agreement.Definition != b.agreement.Definition || a.agreement.TargetPresent != b.agreement.TargetPresent || len(a.members) != len(b.members) {
		return false
	}
	if !a.period.From.Equal(b.period.From) || !a.period.To.Equal(b.period.To) || a.period.Timezone != b.period.Timezone ||
		a.period.BillingDay != b.period.BillingDay || a.period.BoundaryPolicy != b.period.BoundaryPolicy {
		return false
	}
	if (a.circuit == nil) != (b.circuit == nil) {
		return false
	}
	if a.circuit != nil && (a.circuit.Revision != b.circuit.Revision || !slices.Equal(a.circuit.Members, b.circuit.Members)) {
		return false
	}
	for i := range a.members {
		if a.members[i].maximum != b.members[i].maximum || !sameCapacityCounterInterface(a.members[i].target, b.members[i].target) {
			return false
		}
	}
	return true
}
