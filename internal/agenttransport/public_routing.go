// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
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

func (svc *service) submitPublicRoutingEvidence(ctx context.Context, id crypto.SPIFFEID, serial string, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, bool, error) {
	if svc.routingLimits.public.MemoryBytes <= 0 || svc.routingLimits.public.WorkUnits <= 0 || svc.routingLimits.public.StateBytes <= 0 || svc.routingLimits.maxAge <= 0 {
		return nil, false, status.Error(codes.Unavailable, "public routing resource policy is unavailable")
	}
	if req.PublicRoutingPeerTable != nil {
		return svc.stagePublicRoutingSource(ctx, id, serial, req)
	}
	return svc.applyPublicRoutingMessage(ctx, id, serial, req)
}

func (svc *service) stagePublicRoutingSource(ctx context.Context, id crypto.SPIFFEID, serial string, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, bool, error) {
	raw := req.PublicRoutingPeerTable
	admitted := svc.admitEntityEvidence(ctx, id.TenantID, 1, proto.Size(req))
	valid := len(raw.ProtoReflect().GetUnknown()) == 0
	input := store.BGPPublicSnapshotInput{CollectorAgentID: id.AgentID, SenderSerial: serial, SourceRef: raw.ConfiguredRef, ObservationID: raw.ObservationId, ObservedAt: time.Unix(0, raw.ObservedUnixNanos), SourceRecord: raw.SourceRecord}
	var result store.BGPPublicSnapshotStageResult
	err := tenancy.FencedTenantWrite(ctx, svc.fence, id.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), svc.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			result, err = (store.BGPRouting{}).StagePublicMRTSourceInScope(ctx, sc, input, svc.routingLimits.public, admitted && valid)
			return err
		})
	})
	if err != nil {
		return nil, false, status.Error(codes.Unavailable, "current public routing source is unavailable")
	}
	if !admitted {
		return nil, false, status.Error(codes.ResourceExhausted, "tenant public routing evidence rate exceeded")
	}
	if !valid {
		return nil, false, status.Error(codes.InvalidArgument, "public source contains unsupported fields")
	}
	return &agentv1.SubmitEntityEvidenceResponse{PublicRouting: &agentv1.PublicRoutingStagingReceipt{Status: result.Status, SnapshotId: raw.ObservationId}}, result.Status != "invalidated", nil
}

func (svc *service) applyPublicRoutingMessage(ctx context.Context, id crypto.SPIFFEID, serial string, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, bool, error) {
	raw := req.PublicRoutingMessage
	if raw == nil {
		return nil, false, status.Error(codes.InvalidArgument, "public routing operation is missing")
	}
	admitted := raw.SourceReset || svc.admitEntityEvidence(ctx, id.TenantID, 1, proto.Size(req))
	valid := len(raw.ProtoReflect().GetUnknown()) == 0
	input := store.BGPPublicSnapshotMessage{CollectorAgentID: id.AgentID, SenderSerial: serial, SourceRef: raw.ConfiguredRef, SnapshotID: raw.SnapshotId, Sequence: raw.Sequence, ObservedAt: time.Unix(0, raw.ObservedUnixNanos), Complete: raw.Complete, Reset: raw.SourceReset}
	record := raw.Record
	if !admitted || !valid {
		input.Reset, input.Complete = true, false
		record = nil
	}
	var result store.BGPRoutingApplyResult
	err := tenancy.FencedTenantWrite(ctx, svc.fence, id.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), svc.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			result, err = (store.BGPRouting{}).ApplyPublicMRTFrameInScope(ctx, sc, input, record, svc.routingLimits.public, svc.routingLimits.maxAge)
			return err
		})
	})
	if err != nil {
		return nil, false, status.Error(codes.Unavailable, "current public routing message is unavailable")
	}
	if !admitted {
		return nil, false, status.Error(codes.ResourceExhausted, "tenant public routing evidence rate exceeded")
	}
	if !valid {
		return nil, false, status.Error(codes.InvalidArgument, "public message contains unsupported fields")
	}
	return &agentv1.SubmitEntityEvidenceResponse{PublicRoutingMessage: &agentv1.PublicRoutingMessageReceipt{Status: result.Status, SnapshotId: raw.SnapshotId, Sequence: raw.Sequence}}, result.Status != "invalidated", nil
}
