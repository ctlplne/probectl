// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"net/netip"
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

type flowRoutingWitness struct {
	digest [32]byte
	input  entity.FlowCaptureInput
}

// This validates every observation before any write. The request has no
// canonical identity; tenant/sender below come from the already verified,
// issued, currently unrevoked evidence mTLS certificate.
func parseFlowRoutingWitnessBatch(id crypto.SPIFFEID, req *agentv1.SubmitEntityEvidenceRequest, budget store.BGPRoutingBudget) ([]flowRoutingWitness, error) {
	if id.Plane != "entity" || id.TrustDomain != crypto.TrustDomain {
		return nil, status.Error(codes.Unauthenticated, "verified evidence sender is required")
	}
	batch := req.GetFlowRouting()
	if batch == nil || batch.ContractVersion != "flow_capture_v1" || len(batch.Observations) == 0 || len(req.GetObservations())+len(req.GetFaults()) != 0 || req.GetRoutingPeerUp() != nil || req.GetRoutingMessage() != nil || len(req.ProtoReflect().GetUnknown()) != 0 || len(batch.ProtoReflect().GetUnknown()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "flow routing evidence must be a complete exclusive supported batch")
	}
	size := int64(proto.Size(req))
	count := int64(len(batch.Observations))
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 || size > budget.MemoryBytes/8 || size > budget.WorkUnits/8 || count > budget.MemoryBytes/4096 || count > budget.WorkUnits/4096 {
		return nil, status.Error(codes.ResourceExhausted, "complete flow witness batch exceeds resource admission")
	}
	out := make([]flowRoutingWitness, len(batch.Observations))
	for i, raw := range batch.Observations {
		if raw == nil || len(raw.RawDigest) != 32 || len(raw.ProtoReflect().GetUnknown()) != 0 {
			return nil, status.Error(codes.InvalidArgument, "invalid complete flow witness")
		}
		exporter, err := netip.ParseAddr(raw.ExporterAddress)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid flow witness exporter")
		}
		source, err := netip.ParseAddr(raw.SourceAddress)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid flow witness source")
		}
		destination, err := netip.ParseAddr(raw.DestinationAddress)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid flow witness destination")
		}
		out[i].input = entity.FlowCaptureInput{Exporter: exporter.Unmap(), Source: source.Unmap(), Destination: destination.Unmap(), Protocol: raw.FlowProtocol, Domain: raw.ObservationDomain}
		copy(out[i].digest[:], raw.RawDigest)
		if _, err := entity.FlowCaptureKey(id.TenantID, id.AgentID, out[i].digest, out[i].input); err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid scoped flow witness")
		}
	}
	return out, nil
}

func (svc *service) submitFlowRoutingEvidence(ctx context.Context, id crypto.SPIFFEID, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	budget := svc.routingCaptureBudget()
	witnesses, err := parseFlowRoutingWitnessBatch(id, req, budget)
	if err != nil {
		return nil, err
	}
	if !svc.admitEntityEvidence(ctx, id.TenantID, len(witnesses), proto.Size(req)) {
		return nil, status.Error(codes.ResourceExhausted, "tenant flow witness evidence rate exceeded")
	}
	ctx, cancel := context.WithTimeout(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), 30*time.Second)
	defer cancel()
	captures := store.NewBGPRoutingFlowCaptures(svc.pool).WithRPKIEnrichment(svc.routingLimits.rpki)
	response := &agentv1.FlowRoutingCaptureBatch{Captures: make([]*agentv1.FlowRoutingCapture, len(witnesses))}
	for i, witness := range witnesses {
		// Normal scoped Postgres transactions take the existing durable writer
		// fence through their write triggers. No external-store lease or second
		// connection is held across the adapter's independent source snapshot.
		captured, err := captures.CaptureAuthenticated(ctx, id.AgentID, witness.digest, witness.input, budget)
		if err != nil {
			return nil, status.Error(codes.Unavailable, "current authenticated flow routing capture is unavailable")
		}
		response.Captures[i] = &agentv1.FlowRoutingCapture{Key: append([]byte(nil), captured.Key[:]...), CapturedUnixNanos: captured.CapturedAt.UnixNano()}
	}
	return &agentv1.SubmitEntityEvidenceResponse{FlowRouting: response}, nil
}
