// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type interfaceRoleInterfaceBinding struct {
	Scope                           entity.Scope
	RouterID, InterfaceID, SourceID string
	IfIndex                         uint32
	SourceActive                    bool
	Clock                           interfaceRoleClock
}

type interfaceRolePrefixRow struct {
	IfIndex uint32
	Prefix  netip.Prefix
	OnLink  bool
}

type interfaceRolePrefixSnapshot struct {
	Scope              entity.Scope
	RouterID, SourceID string
	Clock              interfaceRoleClock
	SourceActive       bool
	Complete           bool
	Rows               []interfaceRolePrefixRow
}

type interfaceRoleUnboundPeer struct {
	Scope              entity.Scope
	RouterID, SourceID string
	Address            netip.Addr
	ASN                uint32
	SourceActive       bool
	Clock              interfaceRoleClock
}

type interfaceRolePeerAssociation struct {
	Peer   interfaceRolePeer
	Reason string
}

func interfaceRoleAssociationID(id string) bool {
	parsed, err := gouuid.Parse(id)
	return err == nil && parsed != gouuid.Nil && parsed.String() == id
}

// associateInterfaceRolePeer has no IO or identity authority. Its eventual
// loader must prove current tenant/RLS, source/certificate, anchor and parent
// bindings and the completeness of the original prefix walk. A matching raw
// ifIndex alone never supplies a canonical interface (docs/guardrails.md G7-1).
func associateInterfaceRolePeer(ctx context.Context, scope entity.Scope, routerID string, at time.Time,
	peer interfaceRoleUnboundPeer, snapshot interfaceRolePrefixSnapshot, bindings []interfaceRoleInterfaceBinding,
	budget interfaceRoleBudget) (interfaceRolePeerAssociation, error) {
	return associateInterfaceRolePeerAdmitted(ctx, scope, routerID, at, peer, snapshot, bindings, &budget)
}

// A multi-peer operation shares this remaining envelope; no per-peer reset.
func associateInterfaceRolePeerAdmitted(ctx context.Context, scope entity.Scope, routerID string, at time.Time,
	peer interfaceRoleUnboundPeer, snapshot interfaceRolePrefixSnapshot, bindings []interfaceRoleInterfaceBinding,
	budget *interfaceRoleBudget) (interfaceRolePeerAssociation, error) {
	none := interfaceRolePeerAssociation{}
	owned, err := scope.Normalize()
	tenant, ok := tenancy.FromContext(ctx)
	if err != nil || !ok || tenant.String() != owned.TenantID || peer.Scope != owned || snapshot.Scope != owned ||
		peer.RouterID != routerID || snapshot.RouterID != routerID {
		return none, entity.ErrScopeMismatch
	}
	if err := validateInterfaceRoleAssociationInputs(routerID, at, peer, snapshot); err != nil {
		return none, err
	}
	if err := budget.charge(ctx, 1, 4096, 1); err != nil {
		return none, err
	}
	if err := budget.charge(ctx, len(bindings), 2048, 1); err != nil {
		return none, err
	}
	if err := budget.charge(ctx, len(snapshot.Rows), 256, 2); err != nil {
		return none, err
	}
	byIndex, err := interfaceRoleAssociationBindings(ctx, owned, routerID, bindings)
	if err != nil {
		return none, err
	}
	if err := validateInterfaceRolePrefixRows(ctx, snapshot); err != nil {
		return none, err
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if !snapshot.Complete || !snapshot.SourceActive || !peer.SourceActive ||
		!snapshot.Clock.current(at) || !peer.Clock.current(at) {
		return interfaceRolePeerAssociation{Reason: "unavailable_source"}, nil
	}
	// BMP's plain address cannot establish an IPv6 interface zone. Keep it
	// unresolved until a source can prove that scope without flattening it.
	if peer.Address.Zone() != "" || peer.Address.IsLinkLocalUnicast() || peer.Address.IsLinkLocalMulticast() {
		return interfaceRolePeerAssociation{Reason: "unsupported_peer_scope"}, nil
	}
	var match interfaceRoleInterfaceBinding
	ambiguous, unavailable := false, false
	for _, row := range snapshot.Rows {
		if err := ctx.Err(); err != nil {
			return none, err
		}
		if !row.OnLink || row.Prefix.Bits() == 0 || !row.Prefix.Contains(peer.Address) {
			continue
		}
		binding, mapped := byIndex[row.IfIndex]
		if !mapped || !binding.SourceActive || !binding.Clock.current(at) {
			unavailable = true
			continue
		}
		if match.InterfaceID != "" && match.InterfaceID != binding.InterfaceID {
			ambiguous = true
		}
		match = binding
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	if unavailable {
		return interfaceRolePeerAssociation{Reason: "unavailable_interface"}, nil
	}
	if ambiguous {
		return interfaceRolePeerAssociation{Reason: "ambiguous_prefix"}, nil
	}
	if match.InterfaceID == "" {
		return interfaceRolePeerAssociation{Reason: "insufficient_prefix"}, nil
	}
	if err := budget.charge(ctx, 2, 2048, 2); err != nil {
		return none, err
	}
	clock := peer.Clock
	for _, current := range []interfaceRoleClock{snapshot.Clock, match.Clock} {
		if current.ObservedAt.After(clock.ObservedAt) {
			clock.ObservedAt = current.ObservedAt
		}
		if current.ValidUntil.Before(clock.ValidUntil) {
			clock.ValidUntil = current.ValidUntil
		}
	}
	binding := match
	provenance := []string{snapshot.SourceID, binding.SourceID}
	for i := range provenance {
		provenance[i] = strings.Clone(provenance[i])
	}
	slices.Sort(provenance)
	provenance = slices.Compact(provenance)
	return interfaceRolePeerAssociation{Reason: "unique_current_prefix", Peer: interfaceRolePeer{
		Scope: owned, InterfaceID: strings.Clone(match.InterfaceID), SourceID: strings.Clone(peer.SourceID), ASN: peer.ASN,
		SourceActive: true, Clock: clock, AssociationSources: provenance,
	}}, nil
}

func validateInterfaceRoleAssociationInputs(routerID string, at time.Time,
	peer interfaceRoleUnboundPeer, snapshot interfaceRolePrefixSnapshot) error {
	if !interfaceRoleAssociationID(routerID) || at.IsZero() || peer.ASN == 0 ||
		!interfaceRoleSource(peer.SourceID) || !interfaceRoleSource(snapshot.SourceID) ||
		!peer.Clock.valid() || !snapshot.Clock.valid() || !peer.Address.IsValid() ||
		peer.Address.Is4In6() || peer.Address.IsUnspecified() || peer.Address.IsMulticast() {
		return errInterfaceRoleInput
	}
	return nil
}

func interfaceRoleAssociationBindings(ctx context.Context, owned entity.Scope, routerID string,
	bindings []interfaceRoleInterfaceBinding) (map[uint32]interfaceRoleInterfaceBinding, error) {
	byIndex := make(map[uint32]interfaceRoleInterfaceBinding, len(bindings))
	ids := make(map[string]bool, len(bindings))
	for _, binding := range bindings {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if binding.Scope != owned || binding.RouterID != routerID {
			return nil, entity.ErrScopeMismatch
		}
		if !interfaceRoleAssociationID(binding.InterfaceID) || binding.IfIndex == 0 ||
			!interfaceRoleSource(binding.SourceID) || !binding.Clock.valid() || ids[binding.InterfaceID] {
			return nil, errInterfaceRoleInput
		}
		if _, duplicate := byIndex[binding.IfIndex]; duplicate {
			return nil, errInterfaceRoleInput
		}
		byIndex[binding.IfIndex], ids[binding.InterfaceID] = binding, true
	}
	return byIndex, nil
}

func validateInterfaceRolePrefixRows(ctx context.Context, snapshot interfaceRolePrefixSnapshot) error {
	type prefixKey struct {
		index  uint32
		prefix netip.Prefix
	}
	seen := make(map[prefixKey]bool, len(snapshot.Rows))
	for _, row := range snapshot.Rows {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := prefixKey{row.IfIndex, row.Prefix}
		if row.IfIndex == 0 || !row.Prefix.IsValid() || row.Prefix.Masked() != row.Prefix ||
			row.Prefix.Addr().Is4In6() || seen[key] {
			return errInterfaceRoleInput
		}
		seen[key] = true
	}
	return nil
}
