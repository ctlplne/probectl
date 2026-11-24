// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// ReportInstantTestResult stores only the exact signed lease's result. The
// reply acknowledges a committed tenant transaction, including an exact retry.
func (svc *service) ReportInstantTestResult(ctx context.Context, req *agentv1.ReportInstantTestResultRequest) (*agentv1.ReportInstantTestResultResponse, error) {
	id, err := svc.authenticate(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "regular agent identity is required")
	}
	if svc.instantTestPull == nil || svc.pool == nil {
		return nil, status.Error(codes.FailedPrecondition, "instant test distribution is not configured")
	}
	if !isCanonicalInstantID(req.GetRunId()) || !isCanonicalInstantID(req.GetLeaseId()) || !isCanonicalInstantID(req.GetTestId()) {
		return nil, status.Error(codes.InvalidArgument, "invalid instant result lease")
	}
	if len(req.GetResultPayload()) > 64<<10 {
		return nil, status.Error(codes.ResourceExhausted, "instant result payload exceeds its budget")
	}
	var result resultv1.Result
	if err := proto.Unmarshal(req.GetResultPayload(), &result); err != nil || !isCanonicalInstantID(result.GetResultId()) || result.GetStartTimeUnixNano() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid instant result payload")
	}
	leaf, err := peerLeafFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "client certificate is unavailable")
	}
	input := store.InstantRunResult{
		RunID: req.GetRunId(), LeaseID: req.GetLeaseId(), TestID: req.GetTestId(), ResultID: result.GetResultId(),
		StartedAt: time.Unix(0, result.GetStartTimeUnixNano()).UTC(), DurationNanos: result.GetDurationNano(),
		Success: result.GetSuccess(), Outcome: req.GetOutcome(), TestType: result.GetCanaryType(), Metrics: result.GetMetrics(),
	}
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), svc.pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := (store.InstantTestRuns{}).Complete(ctx, sc, id.AgentID, leaf.SerialNumber.Text(16), input)
		return err
	})
	switch {
	case tenancy.IsProspectCollectionEnded(err):
		return nil, status.Error(codes.FailedPrecondition, "prospect collection ended")
	case errors.Is(err, store.ErrInstantRunUnavailable):
		return nil, status.Error(codes.NotFound, "instant test lease is unavailable")
	case errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded):
		return nil, status.FromContextError(err).Err()
	case err != nil:
		return nil, status.Error(codes.Unavailable, "instant result store is unavailable")
	}
	return &agentv1.ReportInstantTestResultResponse{}, nil
}

func isCanonicalInstantID(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
