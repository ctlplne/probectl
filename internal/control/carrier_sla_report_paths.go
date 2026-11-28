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

	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type carrierSLAPathRequirement struct {
	TestID  string `json:"test_id"`
	AgentID string `json:"agent_id"`
	RoundID string `json:"round_id"`
	Digest  string `json:"digest"`
}

type carrierSLAPathOriginal struct {
	TestID      string    `json:"test_id"`
	RoundID     string    `json:"round_id"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	Path        path.Path `json:"path"`
}

func (s *Server) captureCarrierSLAPathOriginals(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, agreement flow.CapacityAgreement, sources []store.IncidentConfiguredTest, requirement *carrierSLAReportRequirement, memory int64, chargeRead func(bytes, rows int64) error) ([]carrierSLAPathOriginal, error) {
	originals := []carrierSLAPathOriginal{}
	if s.pathStore == nil {
		return originals, nil
	}
	selected, err := s.carrierSLACircuitPathSources(ctx, sc, actor, agreement.Definition.Target, sources, memory/2)
	if err != nil {
		return nil, err
	}
	policy := incidentEvidenceTenantPolicy(redactionPolicy(s.cfg), actor.TenantID)
	seen := map[[2]string]bool{}
	for _, source := range selected {
		rounds, err := s.carrierSLAPathRounds(ctx, actor.TenantID, source, requirement.evidencePeriod(), nil, memory/2, chargeRead)
		if err != nil {
			return nil, err
		}
		for _, round := range rounds {
			key := [2]string{source.TestID, round.ID}
			if seen[key] {
				continue
			}
			seen[key] = true
			digest, size, err := carrierSLAPathDigest(round)
			if err != nil {
				return nil, err
			}
			if memory < 2048 || size > (memory-2048)/8 {
				return nil, store.ErrClientReportBudget
			}
			memory -= 2048 + size*8
			p, err := redactCarrierPath(round.Path, policy, actor.TenantID)
			if err != nil {
				return nil, err
			}
			p.Vantage = path.VantageControlPlane
			originals = append(originals, carrierSLAPathOriginal{TestID: source.TestID, RoundID: round.ID, StartedAt: round.ObservedAt, CompletedAt: *round.CompletedAt, Path: p})
			requirement.Paths = append(requirement.Paths, carrierSLAPathRequirement{TestID: source.TestID, AgentID: source.AgentID, RoundID: round.ID, Digest: digest})
		}
	}
	return originals, ctx.Err()
}

func (s *Server) revalidateCarrierSLAPaths(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, agreement flow.CapacityAgreement, sources []store.IncidentConfiguredTest, requirement carrierSLAReportRequirement, memory int64) error {
	if len(requirement.Paths) == 0 {
		return nil
	}
	selected, err := s.carrierSLACircuitPathSources(ctx, sc, actor, agreement.Definition.Target, sources, memory/2)
	if err != nil {
		return err
	}
	wanted := make(map[[2]string][]carrierSLAPathRequirement)
	for _, row := range requirement.Paths {
		key := [2]string{row.TestID, row.AgentID}
		wanted[key] = append(wanted[key], row)
	}
	for _, source := range selected {
		key := [2]string{source.TestID, source.AgentID}
		items := wanted[key]
		if len(items) == 0 {
			continue
		}
		delete(wanted, key)
		ids := make([]string, 0, len(items))
		digests := make(map[string]string, len(items))
		for _, item := range items {
			ids = append(ids, item.RoundID)
			digests[item.RoundID] = item.Digest
		}
		rounds, err := s.carrierSLAPathRounds(ctx, actor.TenantID, source, requirement.evidencePeriod(), ids, memory/2, nil)
		if err != nil {
			return err
		}
		for _, round := range rounds {
			digest, size, err := carrierSLAPathDigest(round)
			if err != nil {
				return err
			}
			if memory < 2048 || size > (memory-2048)/8 || digests[round.ID] != digest {
				return errReportSourceRequirements
			}
			memory -= 2048 + size*8
			delete(digests, round.ID)
		}
		if len(digests) != 0 {
			return errReportSourceRequirements
		}
	}
	if len(wanted) != 0 {
		return errReportSourceRequirements
	}
	return ctx.Err()
}

func (s *Server) carrierSLACircuitPathSources(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, target flow.CapacityTarget, sources []store.IncidentConfiguredTest, memory int64) ([]store.IncidentConfiguredTest, error) {
	bound, ok := tenancy.FromContext(ctx)
	if !ok || bound != sc.Tenant || sc.Q == nil || actor == nil || actor.TenantID != bound.String() {
		return nil, entity.ErrScopeMismatch
	}
	members, _, err := s.capacityBillMembersInScope(ctx, sc, actor, target, memory/2, func(ctx context.Context, record entity.ContextRecord) error {
		return s.authorizeClientReportTests(ctx, actor, entityContextResource(record))
	})
	if err != nil {
		return nil, err
	}
	if memory < 4096 || int64(len(members))+int64(len(sources)) > (memory-4096)/1024 {
		return nil, store.ErrClientReportBudget
	}
	contexts, ids := make([]string, 0, len(members)), make([]string, 0, len(members))
	for _, member := range members {
		if member.Scope.TenantID != actor.TenantID {
			return nil, entity.ErrScopeMismatch
		}
		contexts, ids = append(contexts, member.Scope.ContextID), append(ids, member.InterfaceID)
	}
	rows, err := sc.Q.Query(ctx, `SELECT port.context_id::text,port.parent_entity_id::text
 FROM entities port JOIN unnest($2::uuid[],$3::uuid[]) circuit(context_id,id)
   ON (port.context_id,port.id)=(circuit.context_id,circuit.id)
 WHERE port.tenant_id=$1 AND port.kind='interface' AND port.parent_entity_id IS NOT NULL`,
		actor.TenantID, contexts, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	devices := map[[2]string]bool{}
	for rows.Next() {
		var contextID, deviceID string
		if err := rows.Scan(&contextID, &deviceID); err != nil {
			return nil, err
		}
		devices[[2]string{contextID, deviceID}] = true
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var selected []store.IncidentConfiguredTest
	for _, source := range sources {
		if source.TenantID != actor.TenantID {
			return nil, entity.ErrScopeMismatch
		}
		if source.PathBinding == nil || !devices[[2]string{source.ContextID, source.EntityID}] {
			continue
		}
		binding := source.PathBinding
		if binding.Scope.TenantID != actor.TenantID || binding.Scope.ContextID != source.ContextID || binding.Target != path.TargetHost(source.Target) {
			return nil, entity.ErrScopeMismatch
		}
		selected = append(selected, source)
	}
	return selected, ctx.Err()
}

// The path is context for the selected circuit's probe. Its control-plane
// vantage never establishes where the probe ran or affects the contract math.
func (s *Server) carrierSLAPathRounds(ctx context.Context, tenant string, source store.IncidentConfiguredTest, period flow.CapacityBillingPeriod, ids []string, memory int64, chargeRead func(bytes, rows int64) error) ([]pathstore.Snapshot, error) {
	if s.pathStore == nil || source.PathBinding == nil || source.PathBinding.Scope.TenantID != tenant || memory < 4096 {
		return nil, errReportSourceRequirements
	}
	if !reportRequirementUUID(source.TestID) {
		return nil, errReportSourceRequirements
	}
	query := pathstore.HistoryQuery{
		From: period.From, To: period.To.Add(-time.Nanosecond), IDs: ids,
		TestID: source.TestID, MaxBytes: memory, PersistedOnly: true,
	}
	rounds, err := s.pathStore.History(ctx, tenant, source.PathBinding.Target, query)
	if errors.Is(err, pathstore.ErrHistoryBudget) || errors.Is(err, chclient.ErrResponseTooLarge) {
		return nil, errors.Join(store.ErrClientReportBudget, err)
	}
	if err != nil {
		return nil, err
	}
	since := source.PathBinding.AssignedAt
	if source.CurrentSince.After(since) {
		since = source.CurrentSince
	}
	admitted := rounds[:0]
	for _, round := range rounds {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if round.TestID != source.TestID {
			return nil, entity.ErrScopeMismatch
		}
		if chargeRead != nil {
			body, err := json.Marshal(round)
			if err != nil {
				return nil, err
			}
			if err := chargeRead(int64(len(body)), 1); err != nil {
				return nil, err
			}
		}
		if !round.TrustedDiscoveryTime || round.CompletedAt == nil || round.ObservedAt.Before(period.From) ||
			!round.ObservedAt.After(since) || !round.CompletedAt.Before(period.To) || round.CompletedAt.Before(round.ObservedAt) ||
			round.Path.Target != source.PathBinding.Target {
			continue
		}
		if round.Path.Vantage != "" && round.Path.Vantage != path.VantageControlPlane {
			return nil, entity.ErrInvalidClaim
		}
		admitted = append(admitted, round)
	}
	return admitted, ctx.Err()
}

func carrierSLAPathDigest(round pathstore.Snapshot) (string, int64, error) {
	body, err := json.Marshal(round)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(crypto.Hash(body)), int64(len(body)), nil
}
