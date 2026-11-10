// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"time"

	gouuid "github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

var errPeeringTarget = errors.New("current owned peering target evidence is required")

type peeringTarget struct {
	Scope       entity.Scope
	InterfaceID string
	PeerASN     uint32
	IXID, LANID int64
}

// A target is estimate eligibility, never a session/routing claim or a grant.
// The store/RBAC caller must load this exact owned interface first and recheck
// its complete input digest and both shared source generations at publication.
// Missing or contradictory evidence remains explicitly unavailable.
type peeringTargetEligibility struct {
	Target                        peeringTarget
	RouterID, Reason, InputDigest string
	Eligible                      bool
	AsOf, ValidUntil              time.Time
	PrefixVersion, MemberVersion  string
	PrefixIDs, MembershipIDs      []string
	Role                          interfaceRoleExplanation
}

func evaluatePeeringTarget(ctx context.Context, target peeringTarget, in store.InterfaceRoleInputs, prefixes opendata.IXPrefixSnapshot, members opendata.IXMembershipSnapshot, budget interfaceRoleBudget) (peeringTargetEligibility, error) {
	none := peeringTargetEligibility{}
	if err := peeringTargetScope(ctx, target, in); err != nil {
		return none, err
	}
	part := interfaceRoleBudget{MemoryBytes: budget.MemoryBytes / 8, WorkUnits: budget.WorkUnits / 8}
	if err := part.charge(ctx, 1, 4096, 4096); err != nil {
		return none, err
	}
	out := peeringTargetEligibility{Target: target, RouterID: in.RouterID, AsOf: in.AsOf, Reason: "source_unavailable"}
	if !peeringSourcesCurrent(prefixes, members, in.AsOf) {
		return out, nil
	}
	until, ok, err := peeringInterfaceBinding(ctx, in, part)
	if err != nil {
		return none, err
	}
	if !ok {
		out.Reason = "interface_binding_unavailable"
		return out, nil
	}
	matches, err := prefixes.Match(ctx, in.SNMP.Addresses, part.MemoryBytes, part.WorkUnits)
	if err != nil {
		return none, err
	}
	rolePrefixes := make([]interfaceRoleIXPrefix, 0, len(matches))
	if err := part.charge(ctx, len(matches), 1024, 512); err != nil {
		return none, err
	}
	for _, match := range matches {
		if match.LANID != target.LANID {
			out.Reason = "ix_lan_ambiguous"
			out.PrefixIDs = nil
			return out, nil
		}
		out.PrefixIDs = append(out.PrefixIDs, match.SourceID)
		rolePrefixes = append(rolePrefixes, interfaceRoleIXPrefix{SourceID: match.SourceID, Prefix: match.Prefix, Clock: interfaceRoleClock{ObservedAt: prefixes.ObservedAt, ValidUntil: prefixes.ValidUntil}})
	}
	if len(matches) == 0 {
		out.Reason = "interface_not_on_ix_lan"
		return out, nil
	}
	out.Role, err = explainInterfaceRoleInputs(ctx, in, rolePrefixes, part)
	if err != nil {
		return none, err
	}
	if out.Role.Role != interfaceRoleIX || !out.Role.SNMPCurrent || !out.Role.PrefixCurrent {
		out.Reason = "interface_role_unavailable"
		return out, nil
	}
	out.MembershipIDs, err = members.Members(ctx, target.PeerASN, target.IXID, target.LANID, part.MemoryBytes, part.WorkUnits)
	if err != nil {
		return none, err
	}
	if len(out.MembershipIDs) == 0 {
		out.Reason = "peer_not_on_ix_lan"
		return out, nil
	}
	if err := part.charge(ctx, len(out.MembershipIDs), 512, 128); err != nil {
		return none, err
	}
	original := in
	original.AsOf = time.Time{}
	digest, err := hashFlowRoleInputs(ctx, nil, struct {
		Target   peeringTarget
		Inputs   store.InterfaceRoleInputs
		Prefixes opendata.IXPrefixSnapshot
		Members  opendata.IXMembershipSnapshot
	}{target, original, prefixes, members}, part.MemoryBytes)
	if err != nil {
		return none, err
	}
	out.InputDigest = hex.EncodeToString(digest)
	out.Eligible, out.Reason = true, "current_owned_ix_evidence"
	out.PrefixVersion, out.MemberVersion = prefixes.Version, members.Version
	out.ValidUntil = peeringEarlier(until, peeringEarlier(prefixes.ValidUntil, members.ValidUntil))
	slices.Sort(out.PrefixIDs)
	slices.Sort(out.MembershipIDs)
	return out, ctx.Err()
}

func peeringTargetScope(ctx context.Context, target peeringTarget, in store.InterfaceRoleInputs) error {
	tenant, bound := tenancy.FromContext(ctx)
	scope, err := target.Scope.Normalize()
	if !bound || err != nil || scope != target.Scope || tenant.String() != scope.TenantID || in.Scope != scope || in.InterfaceID != target.InterfaceID {
		return entity.ErrScopeMismatch
	}
	id, err := gouuid.Parse(target.InterfaceID)
	if err != nil || id.String() != target.InterfaceID || in.AsOf.IsZero() || target.PeerASN == 0 || target.IXID <= 0 || target.LANID <= 0 {
		return errPeeringTarget
	}
	return ctx.Err()
}

func peeringSourcesCurrent(prefixes opendata.IXPrefixSnapshot, members opendata.IXMembershipSnapshot, at time.Time) bool {
	return prefixes.Enabled && prefixes.Current && members.Enabled && members.Current &&
		!prefixes.ObservedAt.IsZero() && !members.ObservedAt.IsZero() &&
		!prefixes.ObservedAt.After(at) && !members.ObservedAt.After(at) && prefixes.ValidUntil.After(at) && members.ValidUntil.After(at)
}

func peeringInterfaceBinding(ctx context.Context, in store.InterfaceRoleInputs, budget interfaceRoleBudget) (time.Time, bool, error) {
	if in.SNMP == nil || in.RouterID == "" || in.IfIndex == 0 || !peeringClockCurrent(in.SNMP.InterfaceRoleEvidenceClock, in.AsOf) || !peeringClockCurrent(in.SNMP.PrefixClock, in.AsOf) || in.SNMP.Prefixes == nil {
		return time.Time{}, false, nil
	}
	if err := budget.charge(ctx, len(in.SNMP.Bindings), 512, 128); err != nil {
		return time.Time{}, false, err
	}
	until := peeringEarlier(in.SNMP.ValidUntil, in.SNMP.PrefixClock.ValidUntil)
	found := false
	for _, binding := range in.SNMP.Bindings {
		if err := ctx.Err(); err != nil {
			return time.Time{}, false, err
		}
		if binding.IfIndex != in.IfIndex {
			continue
		}
		if binding.InterfaceID != in.InterfaceID || !peeringClockCurrent(binding.InterfaceRoleEvidenceClock, in.AsOf) {
			return time.Time{}, false, nil
		}
		found = true
		until = peeringEarlier(until, binding.ValidUntil)
	}
	return until, found, ctx.Err()
}

func peeringClockCurrent(clock store.InterfaceRoleEvidenceClock, at time.Time) bool {
	return !clock.ObservedAt.IsZero() && !clock.ObservedAt.After(at) && clock.ValidUntil.After(at)
}

func peeringEarlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
