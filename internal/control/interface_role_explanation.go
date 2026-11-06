// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"slices"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
)

// An explanation is a current classification, never a session-health claim or
// a retained authorization grant. Missing source data remains visible as such.
type interfaceRoleExplanation struct {
	entity.Scope
	InterfaceID   string        `json:"interface_id"`
	Role          interfaceRole `json:"role"`
	Reason        string        `json:"reason"`
	Sources       []string      `json:"sources"`
	AsOf          time.Time     `json:"as_of"`
	SNMPCurrent   bool          `json:"snmp_current"`
	PrefixCurrent bool          `json:"prefix_current"`
}

func roleInputClock(c store.InterfaceRoleEvidenceClock) interfaceRoleClock {
	return interfaceRoleClock{ObservedAt: c.ObservedAt, ValidUntil: c.ValidUntil}
}

// Join only the complete canonical bindings read by the tenant store. A BMP
// address or an ifIndex alone never chooses an interface. All peers share one
// remaining admission envelope, including peers that turn out not to match.
func explainInterfaceRoleInputs(ctx context.Context, in store.InterfaceRoleInputs, ix []interfaceRoleIXPrefix, budget interfaceRoleBudget) (interfaceRoleExplanation, error) {
	none := interfaceRoleExplanation{}
	facts := interfaceRoleFacts{Scope: in.Scope, InterfaceID: in.InterfaceID}
	description := ""
	if snmp := in.SNMP; snmp != nil {
		facts.SourceID, facts.SourceActive, facts.Clock = snmp.SourceID, true, roleInputClock(snmp.InterfaceRoleEvidenceClock)
		facts.Addresses, description = snmp.Addresses, snmp.Description
		if in.Override == nil && snmp.Prefixes != nil {
			if err := budget.charge(ctx, len(snmp.Prefixes), 128, 1); err != nil {
				return none, err
			}
			if err := budget.charge(ctx, len(snmp.Bindings), 512, 1); err != nil {
				return none, err
			}
			prefixes := interfaceRolePrefixSnapshot{Scope: in.Scope, RouterID: in.RouterID,
				SourceID: snmp.PrefixSourceID, Clock: roleInputClock(snmp.PrefixClock), SourceActive: true, Complete: true}
			for _, row := range snmp.Prefixes {
				prefixes.Rows = append(prefixes.Rows, interfaceRolePrefixRow{IfIndex: row.IfIndex, Prefix: row.Prefix, OnLink: row.OnLink})
			}
			bindings := make([]interfaceRoleInterfaceBinding, 0, len(snmp.Bindings))
			for _, binding := range snmp.Bindings {
				bindings = append(bindings, interfaceRoleInterfaceBinding{Scope: in.Scope, RouterID: in.RouterID,
					InterfaceID: binding.InterfaceID, SourceID: binding.SourceID, IfIndex: binding.IfIndex,
					SourceActive: true, Clock: roleInputClock(binding.InterfaceRoleEvidenceClock)})
			}
			unresolved := false
			for _, observed := range in.Peers {
				peer := interfaceRoleUnboundPeer{Scope: in.Scope, RouterID: in.RouterID, SourceID: observed.SourceID,
					Address: observed.Address, ASN: observed.ASN, SourceActive: true, Clock: roleInputClock(observed.InterfaceRoleEvidenceClock)}
				association, err := associateInterfaceRolePeerAdmitted(ctx, in.Scope, in.RouterID, in.AsOf, peer, prefixes, bindings, &budget)
				if err != nil {
					return none, err
				}
				if association.Peer.InterfaceID == in.InterfaceID {
					facts.Peers = append(facts.Peers, association.Peer)
				}
				// An unavailable/ambiguous binding may conceal a contradictory
				// declaration on this interface. Do not classify a partial join.
				if association.Reason == "ambiguous_prefix" || association.Reason == "unavailable_interface" || association.Reason == "unavailable_source" {
					unresolved = true
				}
			}
			if unresolved {
				facts.Peers = nil
			}
		}
	}
	decision, err := evaluateInterfaceRoleConfiguration(ctx, facts, in.Policy, in.Override, description, in.AsOf, ix, budget)
	if err != nil {
		return none, err
	}
	result := interfaceRoleExplanation{Scope: decision.Scope, InterfaceID: decision.InterfaceID, Role: decision.Role,
		Reason: decision.Reason, Sources: decision.Sources, AsOf: decision.AsOf}
	if result.Sources == nil {
		result.Sources = []string{}
	}
	if in.SNMP != nil {
		result.SNMPCurrent = facts.Clock.current(in.AsOf)
		result.PrefixCurrent = result.SNMPCurrent && in.SNMP.Prefixes != nil && roleInputClock(in.SNMP.PrefixClock).current(in.AsOf)
	}
	return result, nil
}

// Publication compares the entire owned source/configuration snapshot, not
// only the winning source. Withdrawal, a competing peer, a changed parent or
// policy reset must invalidate the first computation. AsOf alone advances.
func sameInterfaceRoleInputs(a, b store.InterfaceRoleInputs) bool {
	if a.Scope != b.Scope || a.InterfaceID != b.InterfaceID || a.RouterID != b.RouterID || a.IfIndex != b.IfIndex ||
		a.Policy.Scope != b.Policy.Scope || a.Policy.ID != b.Policy.ID || a.Policy.Revision != b.Policy.Revision ||
		!a.Policy.UpdatedAt.Equal(b.Policy.UpdatedAt) ||
		!slices.Equal(a.Policy.Definition.ProviderASNs, b.Policy.Definition.ProviderASNs) ||
		!slices.Equal(a.Policy.Definition.CustomerASNs, b.Policy.Definition.CustomerASNs) ||
		!slices.Equal(a.Policy.Definition.DescriptionRules, b.Policy.Definition.DescriptionRules) ||
		(a.Override == nil) != (b.Override == nil) || (a.SNMP == nil) != (b.SNMP == nil) || !slices.Equal(a.Peers, b.Peers) {
		return false
	}
	if a.Override != nil && *a.Override != *b.Override {
		return false
	}
	if a.SNMP == nil {
		return true
	}
	x, y := a.SNMP, b.SNMP
	return x.InterfaceRoleEvidenceClock == y.InterfaceRoleEvidenceClock && x.PrefixClock == y.PrefixClock &&
		x.SourceID == y.SourceID && x.PrefixSourceID == y.PrefixSourceID && x.Description == y.Description &&
		(x.Prefixes == nil) == (y.Prefixes == nil) && slices.Equal(x.Addresses, y.Addresses) &&
		slices.Equal(x.Prefixes, y.Prefixes) && slices.Equal(x.Bindings, y.Bindings)
}
