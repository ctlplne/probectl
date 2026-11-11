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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func parseCounterWitness(id crypto.SPIFFEID, req *agentv1.SubmitEntityEvidenceRequest) ([32]byte, entity.CounterCaptureInput, error) {
	none := entity.CounterCaptureInput{}
	if id.TrustDomain != crypto.TrustDomain || id.Plane != "entity" {
		return [32]byte{}, none, status.Error(codes.Unauthenticated, "verified evidence sender is required")
	}
	raw := req.GetDeviceCounter()
	if !validEntityEvidenceEnvelope(req) || raw == nil || raw.ContractVersion != "device_counter_capture_v1" || len(raw.RawDigest) != 32 || len(raw.ProtoReflect().GetUnknown()) != 0 {
		return [32]byte{}, none, status.Error(codes.InvalidArgument, "complete exclusive counter witness is required")
	}
	var digest [32]byte
	copy(digest[:], raw.RawDigest)
	input := entity.CounterCaptureInput{ConfiguredTarget: raw.ConfiguredRef, PollStartedAt: time.Unix(0, raw.PollStartedUnixNanos), PollCompletedAt: time.Unix(0, raw.PollCompletedUnixNanos), PointCount: raw.PointCount}
	if _, err := entity.CounterCaptureKey(id.TenantID, id.AgentID, digest, input); err != nil {
		return [32]byte{}, none, status.Error(codes.InvalidArgument, "invalid complete counter witness")
	}
	return digest, input, nil
}

func (svc *service) submitDeviceCounterEvidence(ctx context.Context, id crypto.SPIFFEID, serial string, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	digest, input, err := parseCounterWitness(id, req)
	if err != nil {
		return nil, err
	}
	// This operation writes one bounded witness, not point_count counter rows.
	// The raw history receiver separately charges its complete point population.
	if !svc.admitEntityEvidence(ctx, id.TenantID, 1, proto.Size(req)) {
		return nil, status.Error(codes.ResourceExhausted, "tenant counter witness evidence rate exceeded")
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), 30*time.Second)
	defer cancel()
	captured, err := store.NewDeviceCounterCaptures(svc.pool).CaptureAuthenticated(ctx, id.AgentID, serial, digest, input, svc.counterCaptureStateLimit())
	if err != nil {
		switch {
		case errors.Is(err, store.ErrEvidenceIdentityInactive):
			return nil, status.Error(codes.Unauthenticated, "counter evidence identity is inactive")
		case errors.Is(err, store.ErrCounterCaptureBudget):
			return nil, status.Error(codes.ResourceExhausted, "tenant counter witness state admission exhausted")
		default:
			return nil, status.Error(codes.FailedPrecondition, "current authenticated counter source is unavailable")
		}
	}
	// A source rebind/erasure may commit after the witness transaction. Check
	// current authority again before acknowledging it to the publisher. Raw
	// history ingestion still rechecks independently at its own publication.
	current, err := store.NewDeviceCounterCaptures(svc.pool).LookupWitness(ctx, id.AgentID, digest, input)
	if err != nil || current.Key != captured.Key || !current.CapturedAt.Equal(captured.CapturedAt) {
		return nil, status.Error(codes.FailedPrecondition, "counter source changed before acknowledgment")
	}
	return &agentv1.SubmitEntityEvidenceResponse{DeviceCounter: &agentv1.DeviceCounterCapture{Key: append([]byte(nil), captured.Key[:]...), CapturedUnixNanos: captured.CapturedAt.UnixNano()}}, nil
}
