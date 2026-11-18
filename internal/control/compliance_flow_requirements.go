// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"context"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/reporting"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Retained lineage is used only to recheck the current reader. The policy and
// raw flow rows never become part of this private authorization envelope.
type complianceFlowRequirements struct {
	Sources   []reporting.ComplianceFlowSource `json:"sources"`
	Originals []flowstore.RoutingCaptureRead   `json:"originals"`
}

func validateComplianceFlowRequirements(ctx context.Context, tenant string, value *complianceFlowRequirements, memory int64) error {
	if value == nil || int64(len(value.Sources)+len(value.Originals)) > memory/1024 {
		return errReportSourceRequirements
	}
	if _, err := complianceFlowMembers(value.Sources); err != nil {
		return errReportSourceRequirements
	}
	var last [32]byte
	for _, read := range value.Originals {
		if err := ctx.Err(); err != nil {
			return err
		}
		key, err := entity.FlowCaptureKey(tenant, read.Sender, read.Witness.RawDigest, read.Witness.Input)
		clock := read.Ref.CapturedAt
		if err != nil || key != read.Ref.Key || bytes.Compare(last[:], key[:]) >= 0 || clock.UnixNano() <= 0 || !time.Unix(0, clock.UnixNano()).Equal(clock) {
			return errReportSourceRequirements
		}
		last = key
	}
	return ctx.Err()
}

func (s *Server) revalidateComplianceFlowScope(ctx context.Context, sc tenancy.Scope, actor *auth.Principal, capture *reportFlowCapture, publication bool) error {
	if actor == nil || actor.TenantID != capture.TenantID || actor.TenantID != sc.Tenant.String() {
		return apierror.Forbidden("current compliance flow tenant scope is unavailable")
	}
	budget, err := s.sourceReportBudget()
	if err != nil {
		return err
	}
	if err := validateComplianceFlowRequirements(ctx, capture.TenantID, capture.ComplianceFlow, budget.MemoryBytes/4); err != nil {
		return err
	}
	members, err := complianceFlowMembers(capture.ComplianceFlow.Sources)
	if err != nil {
		return err
	}
	if publication {
		if capture.controlCapture == nil {
			return errReportSourceRequirements
		}
		if err := flowsnapshot.MatchSourceGenerationInScope(ctx, sc, capture.SourceGeneration); err != nil {
			return apierror.Conflict("compliance flow sources were invalidated during generation").Wrap(err)
		}
		ctx = store.WithReportSourceAuditLock(ctx, sc)
	}
	snapshot, err := s.complianceFlowSourcesInScope(ctx, sc, actor, members, capture.ComplianceFlow.Originals, budget)
	if err != nil {
		return err
	}
	for _, source := range snapshot.sources {
		if source.Kind != entity.Device && source.Kind != entity.Interface {
			return apierror.Forbidden("a selected compliance measurement point is unavailable")
		}
	}
	if len(snapshot.owners) != len(capture.ComplianceFlow.Originals) {
		return errReportSourceRequirements
	}
	for i, owner := range snapshot.owners {
		if !owner.Available || owner.Owner.Scope.TenantID != capture.TenantID || owner.Reference.Key != capture.ComplianceFlow.Originals[i].Ref.Key {
			return apierror.Forbidden("current original flow evidence authority is unavailable")
		}
	}
	if publication && (snapshot.sourceDigest != capture.controlCapture.sourceDigest || snapshot.captureDigest != capture.controlCapture.captureDigest) {
		return apierror.Conflict("compliance flow evidence authority changed before publication")
	}
	return ctx.Err()
}
