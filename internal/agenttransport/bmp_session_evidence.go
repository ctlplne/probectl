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

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// WithBMPSessionSignals wires the scoped detector to the existing incidence
// and notification path when enabled at startup.
func (s *Server) WithBMPSessionSignals(policy store.BMPSessionSignalPolicy, write func(context.Context, tenancy.Scope, []incident.Signal) (func(), error)) *Server {
	s.svc.bmpSessionPolicy = policy
	s.svc.bmpSessionSignals = write
	return s
}

func (svc *service) submitBMPSessionEvidence(ctx context.Context, id crypto.SPIFFEID, serial string,
	request *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	raw := request.GetBmpSessionEvidence()
	if raw == nil || len(raw.ProtoReflect().GetUnknown()) != 0 || len(raw.ConfiguredRef) > 1024 || len(raw.OriginSerial) > 128 ||
		len(raw.ConnectionId) != 36 || raw.ObservedUnixNanos <= 0 || len(raw.Frame) > 1<<20 {
		return nil, status.Error(codes.InvalidArgument, "invalid BMP session evidence envelope")
	}
	if !svc.admitEntityEvidence(ctx, id.TenantID, 1, proto.Size(request)) {
		return nil, status.Error(codes.ResourceExhausted, "tenant BMP session evidence rate exceeded")
	}
	wire, err := proto.MarshalOptions{Deterministic: true}.Marshal(raw)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid BMP session evidence")
	}
	input := store.BMPSessionEvidenceInput{CollectorAgentID: id.AgentID, SenderSerial: serial, SourceRef: raw.ConfiguredRef,
		OriginSerial: raw.OriginSerial, ConnectionID: raw.ConnectionId, Sequence: raw.Sequence,
		ObservedAt: time.Unix(0, raw.ObservedUnixNanos).UTC(), Frame: raw.Frame, TransportClosed: raw.TransportClosed, UpdateWindow: raw.UpdateWindow}
	copy(input.Digest[:], crypto.Hash(wire))
	ctx = tenancy.WithTenant(ctx, tenancy.ID(id.TenantID))
	profile := svc.routingCaptureBudget()
	budget := bgp.PeerMessageBudget{MemoryBytes: min(profile.MemoryBytes, 128<<20), WorkUnits: min(profile.WorkUnits, 4<<20)}
	var retained store.BMPSessionWriteResult
	var published func()
	err = tenancy.FencedTenantWrite(ctx, svc.fence, id.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		return tenancy.InTenant(ctx, svc.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			retained, err = store.RecordBMPSessionEvidenceInScope(ctx, sc, input, budget, svc.bmpSessionPolicy)
			if err != nil || len(retained.Signals) == 0 {
				return err
			}
			if svc.bmpSessionSignals == nil {
				return errors.New("BMP session signal writer unavailable")
			}
			published, err = svc.bmpSessionSignals(ctx, sc, retained.Signals)
			return err
		})
	})
	if err != nil {
		return nil, bmpSessionEvidenceWriteError(err)
	}
	if published != nil {
		published()
	}
	return &agentv1.SubmitEntityEvidenceResponse{BmpSessionEvidence: &agentv1.BmpSessionEvidenceReceipt{
		ConnectionId: input.ConnectionID, Sequence: input.Sequence, EvidenceDigest: input.Digest[:], CoverageGap: retained.CoverageGap,
	}}, nil
}

func bmpSessionEvidenceWriteError(err error) error {
	switch {
	case errors.Is(err, store.ErrBGPRoutingSourceUnavailable), errors.Is(err, entity.ErrScopeMismatch):
		return status.Error(codes.PermissionDenied, "current BMP source assignment is unavailable")
	case errors.Is(err, store.ErrBMPSessionEvidenceConflict):
		return status.Error(codes.AlreadyExists, "BMP connection sequence is conflicting or closed")
	case errors.Is(err, bgp.ErrBMPStatisticsBudget), errors.Is(err, bgp.ErrBMPConnectionBudget),
		errors.Is(err, bgp.ErrBMPPeerUpBudget), errors.Is(err, bgp.ErrBMPPeerDownBudget):
		return status.Error(codes.ResourceExhausted, "BMP session evidence admission exceeded")
	case errors.Is(err, store.ErrBMPSessionEvidenceInput), errors.Is(err, bgp.ErrBMPStatisticsReport),
		errors.Is(err, bgp.ErrBMPConnectionEvent), errors.Is(err, bgp.ErrBMPRouteViewHeader), errors.Is(err, entity.ErrInvalidClaim),
		errors.Is(err, bgp.ErrBMPPeerUp), errors.Is(err, bgp.ErrBMPPeerDown), errors.Is(err, bgp.ErrBMPUpdateWindow):
		return status.Error(codes.InvalidArgument, "invalid original BMP session evidence")
	default:
		return status.Error(codes.Unavailable, "BMP session evidence persistence failed")
	}
}
