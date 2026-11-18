// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

type complianceFlowWindow struct {
	from, to          time.Time
	sources           []store.IncidentImpactSource
	observed          int
	attested          []flowstore.Row
	sourceDigest      string
	captureDigest     string
	publicationDigest string
	originals         []flowstore.RoutingCaptureRead
	rawCoverageGap    bool
}

// readComplianceFlowWindow consumes the entire selected raw time window under
// the caller's report admission. Retained rows missing current original-owner
// evidence count toward the coverage gap and never supply a control verdict.
func (s *Server) readComplianceFlowWindow(ctx context.Context, actor *auth.Principal, members []store.IncidentImpactEntity, from, to time.Time, budget flowstore.ExplorerBudget) (complianceFlowWindow, error) {
	var none complianceFlowWindow
	ctx, err := bindFlowRoleContext(ctx, actor)
	if err != nil {
		return none, err
	}
	if from.IsZero() || !to.After(from) || to.After(time.Now()) {
		return none, apierror.Validation("compliance flow evidence requires a complete past observation window")
	}
	before, err := s.loadComplianceFlowSourceSnapshot(ctx, actor, members, nil, budget)
	if err != nil {
		return none, err
	}
	rows, err := s.complianceRawWindowRows(ctx, actor.TenantID, before.sources, from, to, budget)
	if err != nil {
		var coverage *flowstore.PlanCoverageError
		if errors.As(err, &coverage) {
			return complianceFlowWindow{from: from, to: to, sources: before.sources,
				sourceDigest: before.sourceDigest, rawCoverageGap: true}, nil
		}
		return none, err
	}
	reads, err := flowstore.IncidentTrafficCaptureReferences(ctx, actor.TenantID, rows, budget.MemoryBytes/8)
	if err != nil {
		return none, err
	}
	after, err := s.loadComplianceFlowSourceSnapshot(ctx, actor, members, reads, budget)
	if err != nil {
		return none, err
	}
	if after.sourceDigest != before.sourceDigest {
		return none, apierror.Conflict("compliance flow source ownership changed during collection")
	}
	attested, err := complianceAttestedFlowRows(ctx, actor.TenantID, from, to, rows, after)
	if err != nil {
		return none, err
	}
	// Stable order makes the observation digest and bounded violation
	// examples independent of query-block delivery order.
	slices.SortFunc(attested, func(left, right flowstore.Row) int {
		if order := left.TS.Compare(right.TS); order != 0 {
			return order
		}
		return cmp.Compare(left.RoutingCaptureKey, right.RoutingCaptureKey)
	})
	originals, err := flowstore.IncidentTrafficCaptureReferences(ctx, actor.TenantID, attested, budget.MemoryBytes/8)
	if err != nil {
		return none, err
	}
	publicationDigest, err := complianceSelectedOwnerDigest(ctx, after.owners, originals, budget.MemoryBytes/4)
	if err != nil {
		return none, err
	}
	return complianceFlowWindow{from: from, to: to, sources: after.sources, observed: len(rows), attested: attested,
		sourceDigest: after.sourceDigest, captureDigest: after.captureDigest, publicationDigest: publicationDigest, originals: originals}, nil
}

func (s *Server) complianceRawWindowRows(ctx context.Context, tenant string, sources []store.IncidentImpactSource, from, to time.Time, budget flowstore.ExplorerBudget) ([]flowstore.Row, error) {
	var selected []flowstore.IncidentTrafficSource
	for _, source := range sources {
		selected = append(selected, source.Selections...)
	}
	if len(selected) == 0 {
		return []flowstore.Row{}, ctx.Err()
	}
	batch, err := flowstore.NewReportPlanBatch(ctx, s.flowStore, tenant, 1, budget.MemoryBytes/8, budget.ExecutionLimit)
	if err != nil {
		return nil, err
	}
	defer batch.Close()
	return batch.IncidentTrafficRows(flowstore.IncidentTrafficQuery{TenantID: tenant, From: from, To: to, Series: "raw", Sources: selected})
}

func complianceAttestedFlowRows(ctx context.Context, tenant string, from, to time.Time, rows []flowstore.Row, snapshot complianceFlowSourceSnapshot) ([]flowstore.Row, error) {
	coverage := incidentImpactSourceCoverage(snapshot.sources)
	owners := make(map[string]store.CapturedFlowOwner, len(snapshot.owners))
	for _, owner := range snapshot.owners {
		owners[hex.EncodeToString(owner.Reference.Key[:])] = owner
	}
	attested := rows[:0]
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if row.TenantID != tenant || row.TS.Before(from) || !row.TS.Before(to) {
			return nil, entity.ErrScopeMismatch
		}
		owner, found := owners[row.RoutingCaptureKey]
		if !found || !owner.Available {
			continue
		}
		if owner.Owner.TenantID != tenant {
			return nil, entity.ErrScopeMismatch
		}
		if coverage.covers(row, owner) {
			attested = append(attested, row)
		}
	}
	clear(rows[len(attested):])
	return attested, nil
}

// Owners and originals are returned in capture-key order by the batch reader.
func complianceSelectedOwnerDigest(ctx context.Context, owners []store.CapturedFlowOwner, originals []flowstore.RoutingCaptureRead, limit int64) (string, error) {
	if len(originals) == 0 {
		return "", ctx.Err()
	}
	selected := make([]store.CapturedFlowOwner, 0, len(originals))
	for _, owner := range owners {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if len(selected) < len(originals) && originals[len(selected)].Ref.Key == owner.Reference.Key {
			if !owner.Available {
				return "", entity.ErrScopeMismatch
			}
			selected = append(selected, owner)
		}
	}
	if len(selected) != len(originals) {
		return "", entity.ErrScopeMismatch
	}
	digest, err := hashFlowRoleInputs(ctx, nil, selected, limit)
	return hex.EncodeToString(digest), err
}
