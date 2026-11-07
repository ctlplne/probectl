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

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Staging alone cannot publish a route. Route monitoring, ordered completion,
// reset and lease maintenance must use the same current source before any
// stored routing state becomes available to a flow lookup.
func (svc *service) stageRoutingPeer(ctx context.Context, id crypto.SPIFFEID, serial string, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw := req.GetRoutingPeerUp()
	if raw == nil || req.GetRoutingMessage() != nil || len(req.GetObservations())+len(req.GetFaults()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "routing metadata must be a complete exclusive request")
	}
	admitted := svc.admitEntityEvidence(ctx, id.TenantID, 1, proto.Size(req))
	refusedPeer, unbound := routingRefusalPeer(raw.GetMessage())
	if unbound {
		return nil, status.Error(codes.InvalidArgument, "routing view has no selected source-context binding")
	}
	profile := store.BGPRoutingBudget{MemoryBytes: 128 << 20, WorkUnits: 128 << 20, StateBytes: 1 << 30, LeaseDuration: time.Minute}
	input := store.BGPRoutingPeerUpInput{CollectorAgentID: id.AgentID, SenderSerial: serial, SourceRef: raw.GetConfiguredRef(), OriginSerial: raw.GetOriginSerial(), ObservationID: raw.GetObservationId(), ObservedAt: time.Unix(0, raw.GetObservedUnixNanos()), RefusedPeer: refusedPeer}
	if admitted {
		input.FrameDigest = crypto.Hash(raw.GetMessage())
		peer, families, decodeErr := bgp.DecodeRoutingPeerUp(ctx, raw.GetMessage(), bgp.PeerMessageBudget{MemoryBytes: profile.MemoryBytes / 2, WorkUnits: profile.WorkUnits / 2})
		if decodeErr == nil {
			if peer.Header.View != bgp.BMPLocRIB {
				return nil, status.Error(codes.InvalidArgument, "routing staging requires a selected Loc-RIB source")
			}
			// A router SVID may carry multiple VRFs. Until an explicit current
			// operator selector is bound, only its global view belongs to this
			// source assignment; payload distinguishers cannot select a context.
			if peer.Header.Distinguisher != ([8]byte{}) {
				return nil, status.Error(codes.InvalidArgument, "routing view has no explicit source-context binding")
			}
			metadata := store.BGPRoutingPeer{Type: peer.Header.PeerType, Flags: peer.Header.Flags, Distinguisher: peer.Header.Distinguisher, Address: peer.Header.PeerAddress, ASN: peer.Header.PeerASN, BGPIdentifier: peer.Header.BGPIdentifier, LocalAddress: peer.LocalAddress, LocalPort: peer.LocalPort, RemotePort: peer.RemotePort, SentOpen: peer.SentOpen, ReceivedOpen: peer.ReceivedOpen}
			for _, info := range peer.Information {
				metadata.Information = append(metadata.Information, store.BGPRoutingPeerInformation{Type: info.Type, Value: info.Value})
			}
			for _, family := range families {
				input.Definitions = append(input.Definitions, store.BGPRoutingViewDefinition{Kind: string(peer.Header.View), AFI: family.AFI, SAFI: family.SAFI, Filtered: peer.Header.Filtered, Peer: metadata})
			}
		}
	}
	// Even a metadata refusal retires prior known state under the authenticated
	// current source; report it only after that invalidation commits.
	var result store.BGPRoutingStageResult
	err := tenancy.FencedTenantWrite(ctx, svc.fence, id.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), svc.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			result, err = (store.BGPRouting{}).StagePeerInScope(ctx, sc, input, profile)
			return err
		})
	})
	if err != nil {
		return nil, status.Error(codes.Unavailable, "current routing source staging is unavailable")
	}
	// A refused replacement cannot keep the known prior source current. The
	// bounded control path above commits only invalidation, never route data.
	if !admitted {
		return nil, status.Error(codes.ResourceExhausted, "tenant routing evidence rate exceeded")
	}
	receipt := &agentv1.BmpRoutingStagingReceipt{Status: result.Status}
	for _, view := range result.Views {
		receipt.Views = append(receipt.Views, &agentv1.BmpRoutingViewReference{Id: view.ID, Generation: view.Generation, Afi: uint32(view.AFI), Safi: uint32(view.SAFI)})
	}
	if svc.log != nil {
		svc.log.Info("routing source staging processed", "tenant_id", id.TenantID, "agent_id", id.AgentID, "outcome", result.Status, "views", len(result.Views))
	}
	return &agentv1.SubmitEntityEvidenceResponse{Routing: receipt}, nil
}
