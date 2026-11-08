// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/bgp"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type routingCapturePublicSourceClock struct {
	SnapshotID       string
	AsOf, ValidUntil time.Time
}

type routingCapturePublicClock struct {
	AsOf, ValidUntil time.Time
	Sources          []routingCapturePublicSourceClock
}

func routingCaptureVersion(lookup BGPRoutingFlowLookup) int {
	if lookup.Source.RPKI != nil || lookup.Destination.RPKI != nil {
		return 3
	}
	if lookup.Source.Public != nil || lookup.Destination.Public != nil {
		return 2
	}
	return 1
}

func splitRoutingCapturePublicClock(side *BGPRoutingFlowSide) *routingCapturePublicClock {
	if side.Public == nil {
		return nil
	}
	public := *side.Public
	public.Sources = append([]BGPPublicRoutingLookup(nil), public.Sources...)
	clock := &routingCapturePublicClock{AsOf: public.AsOf, ValidUntil: public.ValidUntil, Sources: make([]routingCapturePublicSourceClock, len(public.Sources))}
	public.AsOf, public.ValidUntil = time.Time{}, time.Time{}
	for i := range public.Sources {
		source := &public.Sources[i]
		clock.Sources[i] = routingCapturePublicSourceClock{SnapshotID: source.SnapshotID, AsOf: source.AsOf, ValidUntil: source.ValidUntil}
		source.AsOf, source.ValidUntil = time.Time{}, time.Time{}
	}
	side.Public = &public
	return clock
}

func restoreRoutingCapturePublicClock(side *BGPRoutingFlowSide, clock *routingCapturePublicClock) error {
	if side.Public == nil {
		if clock != nil {
			return errRoutingCaptureFormat
		}
		return nil
	}
	if clock == nil || len(clock.Sources) != len(side.Public.Sources) {
		return errRoutingCaptureFormat
	}
	if !side.Public.AsOf.IsZero() || !side.Public.ValidUntil.IsZero() {
		return errRoutingCaptureFormat
	}
	side.Public.AsOf, side.Public.ValidUntil = clock.AsOf, clock.ValidUntil
	for i := range side.Public.Sources {
		source := &side.Public.Sources[i]
		if source.SnapshotID != clock.Sources[i].SnapshotID || !source.AsOf.IsZero() || !source.ValidUntil.IsZero() {
			return errRoutingCaptureFormat
		}
		source.AsOf, source.ValidUntil = clock.Sources[i].AsOf, clock.Sources[i].ValidUntil
	}
	return nil
}

func publicRoutingFlowFields(ctx context.Context, public BGPPublicContextLookup, budget BGPRoutingBudget) ([]bgp.RoutingPathFields, []BGPRoutingNextHopAS, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	count := int64(len(public.Paths))
	if count > budget.MemoryBytes/512 || count > budget.WorkUnits/256 {
		return nil, nil, ErrBGPRoutingBudget
	}
	if err := routingBatchCharge(&budget, count*512, count*256); err != nil {
		return nil, nil, err
	}
	paths := make([]BGPRoutingChange, len(public.Paths))
	hops := make([]BGPRoutingNextHopAS, len(public.Paths))
	for i, path := range public.Paths {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		paths[i] = path.Path
		hops[i] = publicRoutingNextHop(path, public.ValidUntil)
	}
	fields, err := routingFlowPathFields(ctx, paths, budget)
	if err != nil {
		return nil, nil, err
	}
	return fields, hops, nil
}

// A public peer ASN establishes a next-hop association only when every
// original next-hop address equals that exact observed peer address. This is
// public collector visibility, never a same-router neighbor/session claim.
func publicRoutingNextHop(path BGPPublicRoutingPath, until time.Time) BGPRoutingNextHopAS {
	unknown := BGPRoutingNextHopAS{Reason: "unresolved_public_next_hop"}
	if len(path.Path.NextHops) == 0 || path.Peer.PeerASN == 0 || path.Peer.PeerASN == 23456 {
		return unknown
	}
	for _, address := range path.Path.NextHops {
		if address.Unmap() != path.Peer.PeerAddress.Unmap() {
			return unknown
		}
	}
	asn := path.Peer.PeerASN
	return BGPRoutingNextHopAS{ASN: &asn, Sources: []string{"public-view/" + path.View.ID + "/" + path.View.Generation}, Reason: "public_peer_observation", ValidUntil: until}
}

func validatePublicRoutingCaptureSide(ctx context.Context, owner InterfaceRoleFlowBinding, side *BGPRoutingFlowSide, at time.Time, budget BGPRoutingBudget) error {
	public := side.Public
	if (side.State != "public_fallback" && side.State != "public_no_prefix") || (side.RouterState != "no_prefix" && side.RouterState != "source_unavailable") || !reflect.DeepEqual(side.Route, BGPRoutingLookup{}) {
		return errRoutingCaptureFormat
	}
	if public.Scope != owner.Scope {
		return entity.ErrScopeMismatch
	}
	if len(public.Sources) == 0 || public.AsOf.IsZero() || public.AsOf.After(at) || !public.ValidUntil.After(at) {
		return errRoutingCaptureFormat
	}
	var selected BGPPublicContextLookup
	var previous [2]string
	for i, source := range public.Sources {
		if err := validateCapturedPublicSource(ctx, owner.Scope, source, at, budget); err != nil {
			return err
		}
		key := [2]string{source.Source.CollectorAgentID, source.Source.SourceRef}
		if i > 0 && (key[0] < previous[0] || key[0] == previous[0] && key[1] <= previous[1]) {
			return errRoutingCaptureFormat
		}
		previous = key
		if source.AsOf.After(selected.AsOf) {
			selected.AsOf = source.AsOf
		}
		if selected.ValidUntil.IsZero() || source.ValidUntil.Before(selected.ValidUntil) {
			selected.ValidUntil = source.ValidUntil
		}
		if source.Prefix.IsValid() && (!selected.Prefix.IsValid() || source.Prefix.Bits() > selected.Prefix.Bits()) {
			selected.Prefix, selected.Paths = source.Prefix, nil
		}
		if source.Prefix.IsValid() && source.Prefix == selected.Prefix {
			selected.Paths = append(selected.Paths, source.Paths...)
		}
	}
	if public.Prefix != selected.Prefix || !reflect.DeepEqual(public.Paths, selected.Paths) || !public.AsOf.Equal(selected.AsOf) || !public.ValidUntil.Equal(selected.ValidUntil) {
		return errRoutingCaptureFormat
	}
	if side.State == "public_no_prefix" {
		if public.Prefix.IsValid() || public.Paths != nil || side.Fields != nil || side.NextHops != nil {
			return errRoutingCaptureFormat
		}
		return nil
	}
	if !public.Prefix.IsValid() || len(public.Paths) == 0 {
		return errRoutingCaptureFormat
	}
	fields, hops, err := publicRoutingFlowFields(ctx, *public, budget)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(fields, side.Fields) || !reflect.DeepEqual(hops, side.NextHops) {
		return errRoutingCaptureFormat
	}
	return nil
}

func validateCapturedPublicSource(ctx context.Context, scope entity.Scope, source BGPPublicRoutingLookup, at time.Time, budget BGPRoutingBudget) error {
	if source.Source.Scope != scope {
		return entity.ErrScopeMismatch
	}
	if err := validatePublicRoutingSource(ctx, tenancy.Scope{Tenant: tenancy.ID(scope.TenantID)}, source.Source); err != nil {
		return err
	}
	parts := strings.SplitN(source.Source.SourceRef, "/", 3)
	if len(parts) != 3 || (parts[0] != "ris" && parts[0] != "routeviews") || (parts[1] != "mrt_table_dump_v2" && parts[1] != "ris_live") || (parts[0] == "routeviews" && parts[1] == "ris_live") || parts[2] == "" || strings.TrimSpace(parts[2]) != parts[2] || !utf8.ValidString(parts[2]) {
		return errRoutingCaptureFormat
	}
	if canonical, err := validRegistryUUID(source.SnapshotID); err != nil || canonical != source.SnapshotID {
		return errRoutingCaptureFormat
	}
	if source.SourceObservedUnixNanos < 0 || source.Source.ObservedAt.After(source.AsOf) || source.AsOf.IsZero() || source.AsOf.After(at) || !source.ValidUntil.After(at) || time.Unix(0, source.SourceObservedUnixNanos).After(source.AsOf) {
		return errRoutingCaptureFormat
	}
	if !source.Prefix.IsValid() {
		if source.Paths != nil {
			return errRoutingCaptureFormat
		}
		return nil
	}
	if source.Prefix.Masked() != source.Prefix || len(source.Paths) == 0 {
		return errRoutingCaptureFormat
	}
	afi := uint16(2)
	if source.Prefix.Addr().Is4() {
		afi = 1
	}
	for _, path := range source.Paths {
		if err := routingBatchCharge(&budget, 256, 256); err != nil {
			return err
		}
		if !validPublicRoutingPeer(path.Peer) || publicRoutingSourceRef(path.Peer) != source.Source.SourceRef || path.View.Generation != source.SnapshotID || path.Path.Prefix != source.Prefix || path.Path.Withdraw || validateRoutingChange(path.Path, afi) != nil {
			return errRoutingCaptureFormat
		}
		if canonical, err := validRegistryUUID(path.View.ID); err != nil || canonical != path.View.ID {
			return errRoutingCaptureFormat
		}
	}
	return nil
}
