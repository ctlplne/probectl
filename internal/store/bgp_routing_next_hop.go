// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"math/bits"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// BGPRoutingNextHopAS is an observed same-router neighbor association, not a
// claim of session health or forwarding. The route's peer ASN and first path
// value are deliberately absent from the resolver. Unknown never means AS0.
type BGPRoutingNextHopAS struct {
	ASN        *uint32   `json:"asn"`
	Sources    []string  `json:"sources"`
	Reason     string    `json:"reason"`
	ValidUntil time.Time `json:"valid_until"`
}

type routingNextHopPeer struct {
	asn        uint32
	conflict   bool
	sources    []string
	validUntil time.Time
}

// RouterPeersInScope reuses the existing current evidence/credential/birth
// predicate for an independently resolved canonical router, without pretending
// that an observed BGP relationship establishes a live session.
func (s *InterfaceRoleInputsStore) RouterPeersInScope(ctx context.Context, sc tenancy.Scope, scope entity.Scope, routerID string, budget entity.InterfaceRolePolicyBudget) ([]InterfaceRolePeerInput, error) {
	want, err := scope.Normalize()
	tenant, ok := tenancy.FromContext(ctx)
	if err != nil || want != scope || !ok || tenant != sc.Tenant || tenant.String() != want.TenantID || sc.Q == nil {
		return nil, entity.ErrScopeMismatch
	}
	if canonical, err := validRegistryUUID(routerID); err != nil || canonical != routerID {
		return nil, entity.ErrInvalidScope
	}
	admission := roleInputAdmission{memory: budget.MemoryBytes, work: budget.WorkUnits}
	if err := admission.charge(ctx, 4096, 1); err != nil {
		return nil, err
	}
	var present int
	if err := sc.Q.QueryRow(ctx, `SELECT 1 FROM entities WHERE tenant_id=$1 AND context_id=$2 AND id=$3 AND kind='device'`, want.TenantID, want.ContextID, routerID).Scan(&present); err != nil {
		return nil, err
	}
	return loadInterfaceRolePeerInputs(ctx, sc, InterfaceRoleInputs{Scope: want, RouterID: routerID}, &admission)
}

func routingNextHopFields(ctx context.Context, paths []BGPRoutingChange, peers []InterfaceRolePeerInput, budget entity.InterfaceRolePolicyBudget) ([]BGPRoutingNextHopAS, error) {
	admission := roleInputAdmission{memory: budget.MemoryBytes, work: budget.WorkUnits}
	if err := admission.charge(ctx, 128, 1); err != nil {
		return nil, err
	}
	if int64(len(peers)) > admission.memory/256 || int64(len(paths)) > admission.memory/128 {
		return nil, entity.ErrInterfaceRoleBudget
	}
	indexed := make(map[netip.Addr]routingNextHopPeer, len(peers))
	for _, peer := range peers {
		if err := admission.charge(ctx, 256+int64(len(peer.SourceID)), int64(64*(1+bits.Len(uint(len(peers)))))); err != nil {
			return nil, err
		}
		id, ok := strings.CutPrefix(peer.SourceID, "evidence/")
		canonical, err := validRegistryUUID(id)
		if !ok || err != nil || canonical != id || !peer.Address.IsValid() || peer.Address.Zone() != "" || peer.Address.Is4In6() || peer.Address.IsUnspecified() || peer.Address.IsMulticast() || peer.ASN == 0 || peer.ObservedAt.IsZero() || !peer.ValidUntil.After(peer.ObservedAt) {
			return nil, entity.ErrInvalidClaim
		}
		group, exists := indexed[peer.Address]
		if !exists {
			group.asn = peer.ASN
			group.validUntil = peer.ValidUntil
		}
		group.conflict = group.conflict || group.asn != peer.ASN || peer.ASN == 23456
		if peer.ValidUntil.Before(group.validUntil) {
			group.validUntil = peer.ValidUntil
		}
		group.sources = append(group.sources, peer.SourceID)
		indexed[peer.Address] = group
	}
	for address, group := range indexed {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		slices.Sort(group.sources)
		group.sources = slices.Compact(group.sources)
		indexed[address] = group
	}
	if int64(len(paths)) > admission.memory/128 || int64(len(paths)) > admission.work {
		return nil, entity.ErrInterfaceRoleBudget
	}
	result := make([]BGPRoutingNextHopAS, 0, len(paths))
	for _, path := range paths {
		field, err := routingNextHopField(ctx, path, indexed, &admission)
		if err != nil {
			return nil, err
		}
		result = append(result, field)
	}
	return result, nil
}

func routingNextHopField(ctx context.Context, path BGPRoutingChange, indexed map[netip.Addr]routingNextHopPeer, admission *roleInputAdmission) (BGPRoutingNextHopAS, error) {
	if err := admission.charge(ctx, 128, 1); err != nil {
		return BGPRoutingNextHopAS{}, err
	}
	field := BGPRoutingNextHopAS{Reason: "unresolved_next_hop"}
	var selected uint32
	var unresolved, conflict bool
	var sources []string
	var validUntil time.Time
	for _, address := range path.NextHops {
		if err := admission.charge(ctx, 0, 1); err != nil {
			return BGPRoutingNextHopAS{}, err
		}
		// A link-local address has no independently proven interface scope.
		// IPv6's accompanying global next hop can still identify the neighbor.
		if !address.IsValid() || address.Zone() != "" {
			return BGPRoutingNextHopAS{}, entity.ErrInvalidClaim
		}
		// Match the canonical address without changing any retained wire value.
		address = address.Unmap()
		if !address.IsGlobalUnicast() || address.IsLinkLocalUnicast() {
			continue
		}
		group, exists := indexed[address]
		if !exists {
			unresolved = true
			continue
		}
		conflict = conflict || group.conflict || (selected != 0 && selected != group.asn)
		if selected == 0 {
			selected = group.asn
		}
		if validUntil.IsZero() || group.validUntil.Before(validUntil) {
			validUntil = group.validUntil
		}
		for _, source := range group.sources {
			if err := admission.charge(ctx, 64+int64(len(source)), int64(64+len(source))*int64(1+bits.Len(uint(len(sources)+len(group.sources))))); err != nil {
				return BGPRoutingNextHopAS{}, err
			}
			sources = append(sources, source)
		}
	}
	if conflict {
		return BGPRoutingNextHopAS{Reason: "next_hop_as_conflict"}, nil
	}
	if unresolved || selected == 0 {
		return field, nil
	}
	slices.Sort(sources)
	if err := ctx.Err(); err != nil {
		return BGPRoutingNextHopAS{}, err
	}
	field.ASN = &selected
	field.Sources = slices.Compact(sources)
	field.ValidUntil = validUntil
	field.Reason = "current_neighbor_observation"
	return field, nil
}

func expireRoutingNextHopFields(side *BGPRoutingFlowSide, at time.Time) {
	for i := range side.NextHops {
		field := &side.NextHops[i]
		if field.ASN != nil && !field.ValidUntil.After(at) {
			*field = BGPRoutingNextHopAS{Reason: "expired_neighbor_observation"}
		}
	}
}
