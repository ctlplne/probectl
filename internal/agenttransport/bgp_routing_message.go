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

func (svc *service) submitRoutingEvidence(ctx context.Context, id crypto.SPIFFEID, serial string, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, bool, error) {
	if req.GetRoutingMessage() != nil {
		response, err := svc.applyRoutingMessage(ctx, id, serial, req)
		return response, err == nil && response.GetRoutingMessage().GetStatus() != "invalidated", err
	}
	response, err := svc.stageRoutingPeer(ctx, id, serial, req)
	return response, err == nil && response.GetRouting().GetStatus() != "invalidated", err
}

func (svc *service) applyRoutingMessage(ctx context.Context, id crypto.SPIFFEID, serial string, req *agentv1.SubmitEntityEvidenceRequest) (*agentv1.SubmitEntityEvidenceResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	raw := req.GetRoutingMessage()
	if raw == nil || req.GetRoutingPeerUp() != nil || len(req.GetObservations())+len(req.GetFaults()) != 0 {
		return nil, status.Error(codes.InvalidArgument, "routing message must be exclusive")
	}
	selector, unbound := routingRefusalPeer(raw.Message)
	if unbound {
		return nil, status.Error(codes.InvalidArgument, "routing message has no complete selected source key")
	}
	admitted := svc.admitEntityEvidence(ctx, id.TenantID, 1, proto.Size(req))

	input := store.BGPRoutingStreamInput{PeerSelector: selector, CollectorAgentID: id.AgentID, SenderSerial: serial, SourceRef: raw.ConfiguredRef,
		OriginSerial: raw.OriginSerial, Generation: raw.Generation, ObservedAt: time.Unix(0, raw.ObservedUnixNanos), Sequence: raw.Sequence,
		Reset: !admitted || raw.SourceReset && !raw.Heartbeat && len(raw.Message) == 0}
	profile := store.BGPRoutingBudget{MemoryBytes: 256 << 20, WorkUnits: 256 << 20, StateBytes: svc.routingStateLimit(), LeaseDuration: time.Minute}
	var result store.BGPRoutingApplyResult
	err := tenancy.FencedTenantWrite(ctx, svc.fence, id.TenantID, entity.ErrScopeMismatch, func(ctx context.Context) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(id.TenantID)), svc.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var err error
			result, err = (store.BGPRouting{}).ApplyPeerMessageInScope(ctx, sc, input, profile,
				func(ctx context.Context, peer store.BGPRoutingPeer, views []store.BGPRoutingStagedView) ([]store.BGPRoutingBatch, error) {
					return decodeRoutingMessage(ctx, raw, peer, views, profile)
				})
			return err
		})
	})
	if err != nil {
		return nil, status.Error(codes.Unavailable, "current routing source message is unavailable")
	}
	// A dropped known frame is uncertainty, not a lease on old attribution.
	// Commit exact-source invalidation even when its data bucket is exhausted;
	// this bounded control path cannot add rows, decode routes or renew a lease.
	if !admitted {
		return nil, status.Error(codes.ResourceExhausted, "tenant routing evidence rate exceeded")
	}
	return &agentv1.SubmitEntityEvidenceResponse{RoutingMessage: &agentv1.BmpRoutingMessageReceipt{Status: result.Status, Generation: raw.Generation, Sequence: raw.Sequence}}, nil
}

// Every admitted raw frame advances every family, so a lost source frame cannot
// be hidden by alternating IPv4 and IPv6 updates. An unaffected family receives
// an ordered liveness record, never an invented End-of-RIB or routing change.
func decodeRoutingMessage(ctx context.Context, raw *agentv1.BmpRoutingMessage, peer store.BGPRoutingPeer, views []store.BGPRoutingStagedView, profile store.BGPRoutingBudget) ([]store.BGPRoutingBatch, error) {
	if raw.SourceReset && raw.Heartbeat || len(raw.Message) == 0 {
		return nil, store.ErrBGPRoutingBatch
	}
	batches := make([]store.BGPRoutingBatch, len(views))
	for i, view := range views {
		batches[i] = store.BGPRoutingBatch{AFI: view.AFI, SAFI: view.SAFI, Heartbeat: true, WireDigest: crypto.Hash(raw.Message)}
	}
	bound := bgp.PeerUp{Header: bgp.BMPRouteViewHeader{PeerType: peer.Type, Flags: peer.Flags, Distinguisher: peer.Distinguisher,
		PeerAddress: peer.Address, PeerASN: peer.ASN, BGPIdentifier: peer.BGPIdentifier, View: bgp.BMPLocRIB, ASNWidth: 4, Filtered: peer.Flags&0x80 != 0},
		LocalAddress: peer.LocalAddress, LocalPort: peer.LocalPort, RemotePort: peer.RemotePort, SentOpen: peer.SentOpen, ReceivedOpen: peer.ReceivedOpen}
	if peer.SourceFormat != "" {
		families := make([]uint16, 0, len(views))
		for _, view := range views {
			if view.SAFI != 1 {
				return nil, store.ErrBGPRoutingView
			}
			families = append(families, view.AFI)
		}
		profile, err := routingSourceProfile(peer.SourceFormat, families)
		if err != nil {
			return nil, err
		}
		bound.SourceProfile = profile
	}
	if raw.SourceReset || raw.Heartbeat {
		reset, err := bgp.DecodeRoutingLifecycle(ctx, raw.Message, bound, bgp.PeerMessageBudget{MemoryBytes: profile.MemoryBytes / 4, WorkUnits: profile.WorkUnits / 4})
		if err != nil || reset != raw.SourceReset || reset {
			return nil, store.ErrBGPRoutingBatch
		}
		return batches, nil
	}
	decoded, err := bgp.DecodeRoutingChanges(ctx, raw.Message, bound, bgp.UpdateFrameBudget{MemoryBytes: profile.MemoryBytes / 4, WorkUnits: profile.WorkUnits / 4})
	if err != nil {
		return nil, err
	}
	for _, group := range decoded.Groups {
		index := -1
		for i, view := range views {
			if group.Family.AFI == view.AFI && group.Family.SAFI == view.SAFI {
				index = i
			}
		}
		if index < 0 || batches[index].EndOfRIB {
			return nil, store.ErrBGPRoutingBatch
		}
		batches[index].Heartbeat, batches[index].EndOfRIB = false, group.EndOfRIB
	}
	return projectRoutingChanges(ctx, batches, decoded, profile)
}

func projectRoutingChanges(ctx context.Context, batches []store.BGPRoutingBatch, decoded bgp.RoutingChanges, profile store.BGPRoutingBudget) ([]store.BGPRoutingBatch, error) {
	if err := admitRoutingProjection(ctx, decoded, profile); err != nil {
		return nil, err
	}
	// BGP processes withdrawals before announcements, including a replacement
	// of the same prefix/path in this one atomic UPDATE.
	for _, withdraw := range []bool{true, false} {
		for _, group := range decoded.Groups {
			for i := range batches {
				if batches[i].AFI != group.Family.AFI || batches[i].SAFI != group.Family.SAFI {
					continue
				}
				prefixes := group.Announced
				if withdraw {
					prefixes = group.Withdrawn
				}
				for _, prefix := range prefixes {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					change := store.BGPRoutingChange{Prefix: prefix.Prefix, HasPathID: prefix.HasPathID, PathID: prefix.PathID, Withdraw: withdraw}
					if !withdraw {
						change.Segments = make([]store.BGPRoutingSegment, len(decoded.Path.Path.Segments))
						for n, segment := range decoded.Path.Path.Segments {
							change.Segments[n] = store.BGPRoutingSegment{Kind: uint8(segment.Kind), Values: segment.Values}
						}
						change.Attributes.Wire = make([]store.BGPRoutingAttribute, len(decoded.Attributes))
						for n, attribute := range decoded.Attributes {
							change.Attributes.Wire[n] = store.BGPRoutingAttribute{Flags: attribute.Flags, Type: attribute.Type, Value: attribute.Value}
						}
						change.NextHops = group.NextHops
					}
					batches[i].Changes = append(batches[i].Changes, change)
				}
			}
		}
	}
	return batches, nil
}

// Account for the complete cross-product of prefix descriptors and source
// attributes before allocating it. Sharing immutable values avoids byte copies,
// but per-path attribute/segment descriptors still consume real memory/work.
func admitRoutingProjection(ctx context.Context, decoded bgp.RoutingChanges, profile store.BGPRoutingBudget) error {
	memory, work := profile.MemoryBytes/4, profile.WorkUnits/4
	descriptor := int64(256) + int64(len(decoded.Attributes))*64 + int64(len(decoded.Path.Path.Segments))*64
	for _, group := range decoded.Groups {
		if err := ctx.Err(); err != nil {
			return err
		}
		count := int64(len(group.Announced))
		if descriptor <= 0 || memory < 0 || work < 0 || count > memory/descriptor || count > work/descriptor {
			return store.ErrBGPRoutingBudget
		}
		memory -= count * descriptor
		work -= count * descriptor
		count = int64(len(group.Withdrawn))
		if count > memory/256 || count > work/256 {
			return store.ErrBGPRoutingBudget
		}
		memory -= count * 256
		work -= count * 256
	}
	return nil
}
