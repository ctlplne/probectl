// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"reflect"
	"strconv"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func carrierSLAInput(input flow.CarrierSLARequest) (time.Time, error) {
	revision, err := strconv.ParseInt(input.Version, 10, 64)
	if err != nil || revision <= 0 || strconv.FormatInt(revision, 10) != input.Version {
		return time.Time{}, apierror.Validation("an exact recorded agreement revision is required")
	}
	at, err := time.Parse(time.RFC3339Nano, input.At)
	if err != nil {
		return time.Time{}, apierror.Validation("an RFC3339 instant selecting the billing period is required")
	}
	return at, nil
}

// The returned publication check owns no new admission. Its caller keeps op
// alive through marshaling/signing and the native protocol's final frame.
func (s *Server) calculateCarrierSLA(op capacityAgreementOperation, id string, input flow.CarrierSLARequest) (flow.CarrierSLAStatement, func(context.Context) error, error) {
	none := flow.CarrierSLAStatement{}
	at, err := carrierSLAInput(input)
	if err != nil {
		return none, nil, err
	}
	ctx := op.request.Context()
	finish := s.beginFlowOperation(ctx, "carrier_sla_calculate")
	initial, sources, err := s.carrierSLASnapshot(ctx, op, id, input.Version, at)
	finish(err)
	if err != nil {
		return none, nil, err
	}
	if op.chargeRetained != nil {
		state, err := json.Marshal([]any{initial, sources})
		if err != nil {
			return none, nil, err
		}
		if err := op.chargeRetained(int64(len(state))); err != nil {
			return none, nil, err
		}
	}
	if op.captureSLA != nil {
		op.captureSLA(initial.Agreement, sources)
	}
	publication := func(ctx context.Context) error {
		current, _, err := s.carrierSLASnapshot(ctx, op, id, input.Version, at)
		if err != nil {
			return err
		}
		if initial.Agreement.ID != current.Agreement.ID || initial.Agreement.TenantID != current.Agreement.TenantID || initial.Agreement.Version != current.Agreement.Version || initial.Agreement.CurrentVersion != current.Agreement.CurrentVersion || !reflect.DeepEqual(initial.Agreement.Definition, current.Agreement.Definition) || !reflect.DeepEqual(initial.Credit, current.Credit) || !reflect.DeepEqual(initial.Sources, current.Sources) {
			return apierror.Unavailable("recorded SLA terms, original receipts or current source authority changed; retry")
		}
		return tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
			return s.revalidateClientReportTestsInScope(ctx, sc, op.actor, sources, op.budget.MemoryBytes/8)
		})
	}
	return initial, publication, nil
}

func (s *Server) carrierSLASnapshot(ctx context.Context, op capacityAgreementOperation, id, version string, at time.Time) (flow.CarrierSLAStatement, []store.IncidentConfiguredTest, error) {
	none := flow.CarrierSLAStatement{}
	if err := s.currentCapacityAgreementActor(ctx, op.actor, false); err != nil {
		return none, nil, err
	}
	var result flow.CarrierSLAStatement
	var sources []store.IncidentConfiguredTest
	err := tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, op.actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, op.actor)
		if err != nil {
			return err
		}
		agreement, err := op.store.CapacityAgreementInScope(ctx, sc, op.actor.UserID, id, version, nil)
		if err != nil {
			return err
		}
		if !agreement.TargetPresent || agreement.Definition.SLA == nil || len(agreement.Definition.SLA.Sources) == 0 || !agreement.SLASourceMetadataTrusted {
			return apierror.Unavailable("complete current circuit and recorded SLA probe links are required")
		}
		period, err := flow.CapacityBillingPeriodAt(ctx, agreement.Definition, at, op.budget.MemoryBytes/8, op.budget.ReadBytes/8)
		if err != nil {
			return err
		}
		for _, instant := range []time.Time{period.From, period.To.Add(-time.Nanosecond)} {
			terms, err := op.store.CapacityAgreementInScope(ctx, sc, op.actor.UserID, id, "", &instant)
			if err != nil {
				return err
			}
			if terms.Version != agreement.Version {
				return apierror.Validation("selected recorded SLA terms must cover the complete billing period")
			}
		}
		authorizeContext := func(ctx context.Context, record entity.ContextRecord) error {
			if record.TenantID != principal.TenantID {
				return entity.ErrScopeMismatch
			}
			return s.authorizeClientReportTests(ctx, principal, entityContextResource(record))
		}
		if _, _, err := s.capacityBillMembersInScope(ctx, sc, principal, agreement.Definition.Target, op.budget.MemoryBytes/8, authorizeContext); err != nil {
			return err
		}
		authorize := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, testID string) error {
			if record.TenantID != principal.TenantID || record.ContextID != member.ContextID {
				return entity.ErrScopeMismatch
			}
			resource := entityContextResource(record)
			resource["entity_id"], resource["test_id"] = member.EntityID, testID
			return s.authorizeClientReportTests(ctx, principal, resource)
		}
		selectors := make([]store.IncidentConfiguredTest, 0, len(agreement.Definition.SLA.Sources))
		for _, source := range agreement.Definition.SLA.Sources {
			selectors = append(selectors, store.IncidentConfiguredTest{TenantID: principal.TenantID, AgentID: source.AgentID, TestID: source.TestID})
		}
		registry := store.NewEntityRegistry(s.pool)
		sources, err = registry.CarrierSLAConfiguredTestsInScope(ctx, sc, id, version, selectors, op.budget.MemoryBytes/8, authorize)
		if err != nil {
			return err
		}
		accumulator, err := newCarrierSLAAccumulator(ctx, sources, period.From, period.To, op.budget.MemoryBytes/4, op.budget.ReadBytes)
		if err != nil {
			return err
		}
		var asOf time.Time
		if err := sc.Q.QueryRow(ctx, `SELECT transaction_timestamp()`).Scan(&asOf); err != nil {
			return err
		}
		limits := store.ConfiguredMeasurementScanBudget{MemoryBytes: op.budget.MemoryBytes / 8, ReadBytes: op.budget.ReadBytes, ReadRows: int64(op.budget.ReadRows), ChargeRead: op.chargeRead}
		if err := registry.WalkConfiguredTestMeasurementsInScope(ctx, sc, sources, period.From, period.To, limits, func(item store.IncidentTestMeasurement) error { return accumulator.observe(ctx, item) }); err != nil {
			return err
		}
		accumulator.partial = asOf.Before(period.To)
		credit, populations, err := accumulator.finish(ctx, *agreement.Definition.SLA, op.budget.MemoryBytes/8, op.budget.ReadBytes/4)
		if err != nil {
			return err
		}
		result = flow.CarrierSLAStatement{Agreement: agreement, Period: period, Credit: credit, Sources: populations, AsOf: asOf, CoverageBasis: "observed_original_populations_only_not_schedule_or_continuous_availability", RepairBasis: "maximum_observed_failed_completion_to_next_successful_completion_not_physical_repair_time", HumanReview: true}
		for _, source := range sources {
			for _, until := range []*time.Time{source.ValidUntil, source.MeasurementIdentityUntil} {
				if until != nil && (result.SourceValidUntil.IsZero() || until.Before(result.SourceValidUntil)) {
					result.SourceValidUntil = *until
				}
			}
		}
		return nil
	})
	if err != nil {
		return none, nil, err
	}
	return result, sources, nil
}

func marshalCarrierSLAStatement(result flow.CarrierSLAStatement, memory, response int64) (json.RawMessage, error) {
	body, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) >= response || int64(len(body)) >= memory/16 {
		return nil, apierror.TooLarge("complete carrier SLA output exceeds resource admission")
	}
	return body, nil
}
