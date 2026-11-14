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
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type changeEffectsInput struct {
	From, To   time.Time
	DataSeries string
}

type changeEffectsResponse struct {
	ContractVersion string                  `json:"contract_version"`
	Preview         bool                    `json:"preview"`
	Original        change.Event            `json:"original"`
	EvaluatedAt     time.Time               `json:"evaluated_at"`
	ValidUntil      *time.Time              `json:"valid_until,omitempty"`
	Before          incident.ImpactPeriod   `json:"before"`
	After           incident.ImpactPeriod   `json:"after"`
	Members         []incident.ImpactMember `json:"members"`
	Tests           []change.EffectTest     `json:"tests"`
	UnresolvedRoot  bool                    `json:"unresolved_root"`
	Interpretation  string                  `json:"interpretation"`
}

type changeEffectsSnapshot struct {
	original change.Event
	impact   incidentImpactSnapshot
}

type changeEffectsPublication struct {
	check incidentEvidenceFinalizer
	close func()
}

func (s *Server) authorizeChangeEffects(ctx context.Context, actor *auth.Principal, resource map[string]string) error {
	for _, permission := range []string{permChangeRead, permFlowRead, "entities.read", "metrics.read", "events.read", permTestRead} {
		if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// Read current configuration and original receipts in one tenant snapshot.
// Membership is derived from the original archive/router binding, never its
// display name, affected prefix, caller-supplied entities or a synthetic incident.
func (s *Server) loadChangeEffectsSnapshot(ctx context.Context, actor *auth.Principal, id string, input changeEffectsInput, reads []flowstore.RoutingCaptureRead, originalTests []store.IncidentTestMeasurement, history bool, budget flowstore.ExplorerBudget) (changeEffectsSnapshot, error) {
	none := changeEffectsSnapshot{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if s.pool == nil || budget.Validate() != nil {
		return none, apierror.Unavailable("change effect source storage or admission is unavailable")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return none, err
	}
	if status != "active" {
		return none, apierror.Forbidden("change effect tenant is inactive")
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	var result changeEffectsSnapshot
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		resource := map[string]string{auth.ResourceTenantKey: actor.TenantID, "change_id": id}
		if err := s.authorizeChangeEffects(ctx, principal, resource); err != nil {
			return err
		}
		limit := budget.MemoryBytes / 8
		original, inputs, err := (store.ChangeEvents{}).EffectInputsInScope(ctx, sc, id, limit)
		if err != nil {
			return err
		}
		if !input.From.Before(change.EffectAt(original)) || !change.EffectAt(original).Before(input.To) {
			return apierror.Validation("comparison window must include both sides of the original change")
		}
		authorize := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity) error {
			if record.TenantID != principal.TenantID || record.ContextID != member.ContextID {
				return entity.ErrScopeMismatch
			}
			resource := entityContextResource(record)
			resource["change_id"], resource["entity_id"] = id, member.EntityID
			return s.authorizeChangeEffects(ctx, principal, resource)
		}
		sources, err := (store.Incidents{}).ImpactSourcesInScope(ctx, sc, inputs,
			entity.InterfaceRolePolicyBudget{MemoryBytes: limit, WorkUnits: limit}, authorize)
		if err != nil {
			return err
		}
		if original.Config != nil {
			if err := (store.ChangeEvents{}).VerifyConfigChangeReferencesInScope(ctx, sc, []change.Event{original}, limit); err != nil {
				return err
			}
		}
		if original.Routing != nil {
			if err := (store.ChangeEvents{}).VerifyRoutingChangeReferencesInScope(ctx, sc, []change.Event{original}, limit, s.routingChangeAuthorizer(principal, permChangeRead)); err != nil {
				return err
			}
		}
		authorizeTest := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, testID string) error {
			if err := authorize(ctx, record, member); err != nil {
				return err
			}
			resource := entityContextResource(record)
			resource["change_id"], resource["entity_id"], resource["test_id"] = id, member.EntityID, testID
			return s.authorize(ctx, principal, permTestRead, auth.RBACGlobal, resource)
		}
		tests, err := (store.Incidents{}).ConfiguredImpactTestsInScope(ctx, sc, inputs, limit, authorizeTest)
		if err != nil {
			return err
		}
		digest, err := hashFlowRoleInputs(ctx, nil, struct {
			Original change.Event
			Inputs   *store.IncidentImpactInputs
			Sources  []store.IncidentImpactSource
			Tests    []store.IncidentConfiguredTest
		}{original, inputs, sources, tests}, limit)
		if err != nil {
			return err
		}
		result = changeEffectsSnapshot{original: original, impact: incidentImpactSnapshot{authority: current, inputs: inputs, sources: sources, tests: tests, sourceDigest: hex.EncodeToString(digest)}}
		if history {
			// The index is quantized but version3 retains the original clock.
			// Include the boundary bucket, then classify each exact receipt in
			// the complete projection. Legacy ambiguity never becomes a value.
			result.impact.testReads, err = (store.Incidents{}).IncidentWindowTestMeasurementsInScope(ctx, sc, tests, input.From.Truncate(time.Microsecond), input.To, limit)
		} else if originalTests != nil {
			err = (store.Incidents{}).RecheckIncidentTestMeasurementsInScope(ctx, sc, originalTests, limit)
		}
		if err != nil {
			return err
		}
		if len(reads) == 0 {
			return nil
		}
		authorizeOwner := func(ctx context.Context, record entity.ContextRecord, binding store.InterfaceRoleFlowBinding) error {
			for _, source := range sources {
				if source.Member.ContextID != record.ContextID {
					continue
				}
				for _, selected := range source.Selections {
					if selected.AgentID == binding.AgentID && selected.Exporter == binding.Exporter && selected.Protocol == binding.Protocol && selected.Domain == binding.Domain {
						return authorize(ctx, record, source.Member)
					}
				}
			}
			return entity.ErrScopeMismatch
		}
		owners, err := (store.CapturedFlowOwners{}).ReadInScope(ctx, sc, reads,
			store.BGPRoutingBudget{MemoryBytes: limit, WorkUnits: limit, StateBytes: limit}, authorizeOwner)
		if err != nil {
			return err
		}
		digest, err = hashFlowRoleInputs(ctx, nil, owners, limit)
		if err != nil {
			return err
		}
		result.impact.owners, result.impact.captureDigest = owners, hex.EncodeToString(digest)
		return nil
	})
	if err != nil {
		if errors.Is(err, store.ErrClientReportBudget) || errors.Is(err, store.ErrIncidentImpactBudget) {
			return none, apierror.TooLarge("change comparison exceeds configured query admission")
		}
		return none, flowRoutingQueryError(err)
	}
	return result, nil
}

// The publication check is retained through native framing by native callers.
// The same exact originals and current source/identity checks guard HTTP output.
func (s *Server) computeChangeEffects(ctx context.Context, scope *configEvidenceScope, id string, input changeEffectsInput) (_ changeEffectsResponse, _ *changeEffectsPublication, operationErr error) {
	finish := s.beginFlowOperation(ctx, "change_effects")
	defer func() { finish(operationErr) }()
	none := changeEffectsResponse{}
	if scope == nil || scope.actor == nil || scope.actor.UserID == "" || scope.credential == nil {
		return none, nil, apierror.Unauthorized("a current tenant user is required")
	}
	ctx, err := bindFlowRoleContext(ctx, scope.actor)
	if err != nil {
		return none, nil, err
	}
	if input.From.IsZero() || input.To.IsZero() {
		return none, nil, apierror.Validation("explicit comparison from/to are required")
	}
	plan, err := flow.NormalizeQueryPlan(flow.QueryPlan{From: input.From, To: input.To, DataSeries: input.DataSeries}, time.Now().UTC())
	if err != nil {
		return none, nil, apierror.Validation(err.Error())
	}
	input.From, input.To = plan.From, plan.To
	if s.fairnessGate == nil {
		return none, nil, apierror.Unavailable("change effect query admission is unavailable")
	}
	done, err := s.fairnessGate.BeginQuery(ctx, scope.actor.TenantID)
	if err != nil {
		return none, nil, err
	}
	cleanup, retained := done, false
	defer func() {
		if !retained {
			cleanup()
		}
	}()
	budget := flowstore.ExplorerOperationBudget(ctx, s.flowStore)
	budget.MemoryBytes /= 2
	batch, err := flowstore.NewPlanBatch(ctx, s.flowStore, scope.actor.TenantID, 2, 2)
	if err != nil {
		return none, nil, flowExplorerStoreError(err)
	}
	cleanup = func() { batch.Close(); done() }
	ctx = batch.Context()
	before, err := s.loadChangeEffectsSnapshot(ctx, scope.actor, id, input, nil, nil, true, budget)
	if err != nil {
		return none, nil, err
	}
	at := change.EffectAt(before.original)
	plan.From = at
	rows, periods, reads, err := readIncidentImpactTraffic(ctx, scope.actor.TenantID, batch, before.impact, plan, input.From, at, budget.MemoryBytes/8)
	if err != nil {
		return none, nil, err
	}
	observed, err := s.loadChangeEffectsSnapshot(ctx, scope.actor, id, input, reads, before.impact.testReads, false, budget)
	if err != nil {
		return none, nil, err
	}
	if before.impact.sourceDigest != observed.impact.sourceDigest {
		return none, nil, apierror.Unavailable("change or current source membership changed; retry")
	}
	owners := bindIncidentTrafficCoverage(observed.impact, rows)
	for i := range periods {
		periods[i], err = summarizeIncidentTraffic(ctx, scope.actor.TenantID, periods[i], rows[i], owners, budget.MemoryBytes/8)
		if err != nil {
			return none, nil, err
		}
	}
	tests, err := summarizeChangeEffectTests(ctx, scope.actor.TenantID, observed.impact.tests, before.impact.testReads, input.From, at, input.To, budget.MemoryBytes/8)
	if err != nil {
		return none, nil, flowExplorerStoreError(err)
	}
	result := changeEffectsResponse{ContractVersion: "probectl.change-effects.v1", Preview: true, Original: before.original, EvaluatedAt: time.Now().UTC(),
		Before: periods[1], After: periods[0], Members: []incident.ImpactMember{}, Tests: tests, UnresolvedRoot: before.impact.inputs.RootUnresolved,
		Interpretation: "Original retained measurements before and after this exact change, selected through current explicit source bindings. Missing observations or original RTTs are unknown. Current topology membership is not historical topology. Observed changes do not establish causation."}
	for _, source := range observed.impact.sources {
		result.Members = append(result.Members, incident.ImpactMember{ContextID: source.Member.ContextID, EntityID: source.Member.EntityID, Kind: string(source.Kind), IncidentRoot: source.Member.IncidentRoot,
			SignalIDs: []string{}, Reason: source.Reason, SourceIDs: append([]string{}, source.Evidence...)})
	}
	if err := scope.retain(before.original); err != nil {
		return none, nil, err
	}
	validate := func(publicationContext context.Context) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := publicationContext.Err(); err != nil {
			return err
		}
		after, err := s.loadChangeEffectsSnapshot(ctx, scope.actor, id, input, reads, before.impact.testReads, false, budget)
		if err != nil {
			return err
		}
		if observed.impact.sourceDigest != after.impact.sourceDigest || observed.impact.captureDigest != after.impact.captureDigest {
			return apierror.Unavailable("change or original source authority changed before publication; retry")
		}
		validity := incident.ImpactResponse{}
		if err := bindIncidentImpactValidUntil(&validity, after.impact); err != nil {
			return err
		}
		result.ValidUntil = validity.ValidUntil
		if err := scope.check(ctx); err != nil {
			return err
		}
		if err := scope.credential(ctx); err != nil {
			return err
		}
		body, err := json.Marshal(result)
		if err != nil {
			return err
		}
		if int64(len(body)) > budget.ResponseBytes {
			return flowExplorerStoreError(flowstore.ErrExplorerBudget)
		}
		return ctx.Err()
	}
	if err := validate(ctx); err != nil {
		return none, nil, err
	}
	retained = true
	return result, &changeEffectsPublication{check: validate, close: cleanup}, nil
}
