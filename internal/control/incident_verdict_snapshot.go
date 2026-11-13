// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type incidentVerdictSnapshot struct {
	inputs   *store.IncidentImpactInputs
	sources  []store.IncidentInterfaceStateSource
	tests    []store.IncidentConfiguredTest
	roles    []store.InterfaceRoleInputs
	states   []store.IncidentInterfaceStateMeasurement
	outcomes []store.IncidentTestMeasurement
	evidence incidentVerdictEvidence
	digest   string
}

func (s *Server) authorizeIncidentVerdict(ctx context.Context, actor *auth.Principal, resource map[string]string) error {
	permissions := []string{permIncidentRead, "entities.read", "metrics.read", "events.read", permTestRead}
	if exporting, _ := ctx.Value(incidentImpactExportKey{}).(bool); exporting {
		permissions = append(permissions, permAIQuery)
	}
	for _, permission := range permissions {
		if err := s.authorize(ctx, actor, permission, auth.RBACGlobal, resource); err != nil {
			return err
		}
	}
	return ctx.Err()
}

// loadIncidentVerdictSnapshot resolves complete membership and current grants
// before observations. With original present it reads only those retained IDs;
// a newly arriving observation never replaces a citation during publication.
func (s *Server) loadIncidentVerdictSnapshot(ctx context.Context, actor *auth.Principal, id string, from, to time.Time, maxBytes int64, original *incidentVerdictSnapshot) (incidentVerdictSnapshot, error) {
	none := incidentVerdictSnapshot{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if original != nil && (original.inputs == nil || original.inputs.TenantID != actor.TenantID || original.inputs.IncidentID != id ||
		original.evidence.tenantID != actor.TenantID || !original.evidence.from.Equal(from) || !original.evidence.to.Equal(to)) {
		return none, entity.ErrScopeMismatch
	}
	if s.pool == nil || maxBytes < 1<<16 {
		return none, apierror.Unavailable("incident verdict storage or admission is unavailable")
	}
	status, err := NewTenantStatusCache(s.pool, 0).TenantStatus(ctx, actor.TenantID)
	if err != nil {
		return none, err
	}
	if status != "active" {
		return none, apierror.Forbidden("incident verdict tenant is inactive")
	}
	ctx, flush := scopedABACDenial(ctx)
	defer flush(s)
	out := incidentVerdictSnapshot{evidence: incidentVerdictEvidence{tenantID: actor.TenantID, from: from, to: to}}
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		current, err := readCurrentUserAuthorityScope(ctx, sc, actor.UserID)
		if err != nil {
			return err
		}
		ctx, principal, err := current.requestContext(ctx, actor)
		if err != nil {
			return err
		}
		if err := s.authorizeIncidentVerdict(ctx, principal, map[string]string{auth.ResourceTenantKey: actor.TenantID, "incident_id": id}); err != nil {
			return err
		}
		limit := maxBytes / 8
		out.inputs, err = (store.Incidents{}).ImpactInputs(ctx, sc, id, limit)
		if err != nil {
			return err
		}
		authorize := func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity) error {
			if record.TenantID != actor.TenantID || record.ContextID != member.ContextID {
				return entity.ErrScopeMismatch
			}
			resource := entityContextResource(record)
			resource["incident_id"], resource["entity_id"] = id, member.EntityID
			return s.authorizeIncidentVerdict(ctx, principal, resource)
		}
		out.sources, err = (store.Incidents{}).InterfaceStateSourcesInScope(ctx, sc, out.inputs,
			entity.InterfaceRolePolicyBudget{MemoryBytes: limit, WorkUnits: limit}, authorize)
		if err != nil {
			return err
		}
		out.tests, err = (store.Incidents{}).ConfiguredImpactTestsInScope(ctx, sc, out.inputs, limit,
			func(ctx context.Context, record entity.ContextRecord, member store.IncidentImpactEntity, testID string) error {
				if err := authorize(ctx, record, member); err != nil {
					return err
				}
				resource := entityContextResource(record)
				resource["incident_id"], resource["entity_id"], resource["test_id"] = id, member.EntityID, testID
				return s.authorize(ctx, principal, permTestRead, auth.RBACGlobal, resource)
			})
		if err != nil {
			return err
		}
		if original == nil {
			out.states, err = (store.Incidents{}).InterfaceStateMeasurementsInScope(ctx, sc, out.sources, from, to, limit, authorize)
			if err == nil {
				out.outcomes, err = (store.Incidents{}).IncidentTestMeasurementsInScope(ctx, sc, out.tests, from, to, limit)
			}
		} else {
			err = (store.Incidents{}).RecheckInterfaceStateMeasurementsInScope(ctx, sc, out.sources, original.states, limit, authorize)
			if err == nil {
				err = (store.Incidents{}).RecheckIncidentTestMeasurementsInScope(ctx, sc, original.outcomes, limit)
			}
		}
		if err != nil {
			return err
		}
		return s.joinIncidentVerdictSnapshot(ctx, sc, principal, &out, limit)
	})
	if err != nil {
		return none, err
	}
	return out, ctx.Err()
}

// Join on compound canonical keys. Same-tenant address/name similarity cannot
// introduce an incident member, interface, configured test or source agent.
func (s *Server) joinIncidentVerdictSnapshot(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, snapshot *incidentVerdictSnapshot, limit int64) error {
	digest, err := hashFlowRoleInputs(ctx, nil, struct {
		Inputs  *store.IncidentImpactInputs
		Sources []store.IncidentInterfaceStateSource
		Tests   []store.IncidentConfiguredTest
	}{snapshot.inputs, snapshot.sources, snapshot.tests}, limit)
	if err != nil {
		return err
	}
	members := map[string]bool{}
	for _, member := range snapshot.inputs.Entities {
		members[member.ContextID+":"+member.EntityID] = true
	}
	stateReads := map[string][]store.IncidentInterfaceStateMeasurement{}
	for _, read := range snapshot.states {
		key := read.ContextID + ":" + read.EntityID
		stateReads[key] = append(stateReads[key], read)
	}
	roleBytes := limit
	for _, source := range snapshot.sources {
		key := source.ContextID + ":" + source.EntityID
		if !members[key] || !source.Current {
			continue
		}
		role, fingerprint, err := s.incidentVerdictInterfaceRole(ctx, sc, actor, source, &roleBytes)
		if err != nil {
			return err
		}
		digest, err = hashFlowRoleInputs(ctx, digest, fingerprint, limit)
		if err != nil {
			return err
		}
		snapshot.roles = append(snapshot.roles, fingerprint)
		snapshot.evidence.interfaces = append(snapshot.evidence.interfaces, incidentVerdictInterface{source: source, role: role, reads: stateReads[key], direct: true})
	}
	testReads := map[string][]store.IncidentTestMeasurement{}
	for _, read := range snapshot.outcomes {
		key := read.ContextID + ":" + read.EntityID + ":" + read.AgentID + ":" + read.TestID
		testReads[key] = append(testReads[key], read)
	}
	for _, source := range snapshot.tests {
		key := source.ContextID + ":" + source.EntityID + ":" + source.AgentID + ":" + source.TestID
		snapshot.evidence.tests = append(snapshot.evidence.tests, incidentVerdictTest{source: source, reads: testReads[key]})
	}
	snapshot.digest = hex.EncodeToString(digest)
	return ctx.Err()
}

// No IX feed is necessary to prove an owned backbone role. Other roles still
// remain unclassified here; peer relationship metadata is not session health.
func (s *Server) incidentVerdictInterfaceRole(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, source store.IncidentInterfaceStateSource, remaining *int64) (interfaceRoleExplanation, store.InterfaceRoleInputs, error) {
	none := interfaceRoleExplanation{}
	record, err := store.NewEntityRegistry(s.pool).GetEntityContextInScope(ctx, sc, source.ContextID)
	if err != nil {
		return none, store.InterfaceRoleInputs{}, err
	}
	resource := entityContextResource(record)
	resource["entity_id"] = source.EntityID
	if err := s.authorize(ctx, actor, entitySourcePermission(entity.BMPPeer), auth.RBACGlobal, resource); err != nil {
		return none, store.InterfaceRoleInputs{}, err
	}
	if *remaining < 4096 {
		return none, store.InterfaceRoleInputs{}, store.ErrIncidentImpactBudget
	}
	budget := entity.InterfaceRolePolicyBudget{MemoryBytes: *remaining, WorkUnits: *remaining}
	inputs, err := store.NewInterfaceRoleInputs(s.pool).LoadInScope(ctx, sc,
		entity.Scope{TenantID: sc.Tenant.String(), ContextID: source.ContextID}, source.EntityID, budget)
	if err != nil {
		return none, store.InterfaceRoleInputs{}, err
	}
	role, err := explainInterfaceRoleInputs(ctx, inputs, nil, interfaceRoleBudget{MemoryBytes: *remaining, WorkUnits: *remaining})
	if err != nil {
		return none, store.InterfaceRoleInputs{}, err
	}
	// Charge retained source data before the next interface gets the remaining
	// allowance. This is one complete cohort budget, never one budget per row.
	size, err := incidentVerdictRoleInputSize(inputs)
	if err != nil || size > *remaining {
		if err == nil {
			err = store.ErrIncidentImpactBudget
		}
		return none, store.InterfaceRoleInputs{}, err
	}
	*remaining -= size
	inputs.AsOf = time.Time{} // Only the evaluation clock advances between reads.
	return role, inputs, nil
}

// computeIncidentVerdict's final read reauthorizes actual user/credential,
// complete membership and current source policy, then original selectors.
func (s *Server) computeIncidentVerdict(ctx context.Context, actor *auth.Principal, id string, from, to time.Time, maxBytes int64) (incident.FaultVerdict, error) {
	return s.computeIncidentVerdictWithHeader(ctx, actor, id, from, to, maxBytes, nil)
}

func (s *Server) computeIncidentVerdictWithHeader(ctx context.Context, actor *auth.Principal, id string, from, to time.Time, maxBytes int64, captured **store.IncidentImpactInputs) (incident.FaultVerdict, error) {
	return s.computeIncidentVerdictWithPublication(ctx, actor, id, from, to, maxBytes, captured, nil)
}

func (s *Server) computeIncidentVerdictWithPublication(ctx context.Context, actor *auth.Principal, id string, from, to time.Time, maxBytes int64, captured **store.IncidentImpactInputs, publication *incidentEvidenceFinalizer) (incident.FaultVerdict, error) {
	if publication != nil {
		*publication = nil
	}
	if captured != nil {
		*captured = nil
	}
	none := incident.FaultVerdict{}
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	parsed, err := gouuid.Parse(id)
	if err != nil || parsed == gouuid.Nil || parsed.String() != id {
		return none, apierror.Validation("canonical incident identity is required")
	}
	if from.IsZero() || !to.After(from) || to.After(time.Now().UTC()) {
		return none, apierror.Validation("explicit past incident verdict from/to are required")
	}
	before, err := s.loadIncidentVerdictSnapshot(ctx, actor, id, from, to, maxBytes/2, nil)
	if err != nil {
		return none, err
	}
	result, err := classifyIncidentVerdict(ctx, before.evidence, maxBytes/4)
	if err != nil {
		return none, err
	}
	if before.inputs.RootUnresolved || len(before.inputs.UnresolvedSignalIDs) != 0 {
		result.Domain, result.Confidence, result.Reason = incident.FaultUnknown, "insufficient", "incomplete_canonical_incident_membership"
		for i := range result.Hypotheses {
			result.Hypotheses[i].Missing = append(result.Hypotheses[i].Missing, "complete_canonical_incident_membership")
		}
	}
	result.ContractVersion, result.Preview, result.IncidentID = "probectl.incident-verdict.v1", true, id
	result.EvaluatedAt = time.Now().UTC()
	exporting, _ := ctx.Value(incidentImpactExportKey{}).(bool)
	validate := func(ctx context.Context) error {
		if exporting {
			ctx = context.WithValue(ctx, incidentImpactExportKey{}, true)
		}

		after, err := s.loadIncidentVerdictSnapshot(ctx, actor, id, from, to, maxBytes/2, &before)
		if err != nil {
			return err
		}
		if before.digest != after.digest {
			return apierror.Unavailable("incident membership or source authority changed; retry")
		}
		if err := incidentVerdictSnapshotStillCurrent(after, &result); err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if captured != nil {
			*captured = after.inputs
		}
		return nil
	}
	if err := validate(ctx); err != nil {
		return none, err
	}
	if publication != nil {
		*publication = validate
	}

	return result, nil
}
