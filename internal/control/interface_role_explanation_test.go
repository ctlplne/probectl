// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func roleExplanationFixture(tenant string) store.InterfaceRoleInputs {
	facts, _, at := interfaceRoleFixture(tenant)
	clock := store.InterfaceRoleEvidenceClock{ObservedAt: facts.Clock.ObservedAt, ValidUntil: facts.Clock.ValidUntil}
	return store.InterfaceRoleInputs{Scope: facts.Scope, InterfaceID: facts.InterfaceID, RouterID: roleAssociationRouter,
		IfIndex: 4000000001, AsOf: at, Policy: interfaceRoleEvaluationRecord(facts),
		SNMP: &store.InterfaceRoleSNMPInputs{InterfaceRoleEvidenceClock: clock, SourceID: facts.SourceID,
			PrefixSourceID: "prefix-" + tenant, PrefixClock: clock, Description: "Transit é 線", Addresses: facts.Addresses,
			Prefixes: []entity.SNMPInterfacePrefix{{IfIndex: 4000000001, Prefix: netip.MustParsePrefix("198.51.100.0/24"), OnLink: true}},
			Bindings: []store.InterfaceRoleBindingInput{{InterfaceRoleEvidenceClock: clock, InterfaceID: facts.InterfaceID, SourceID: "binding-" + tenant, IfIndex: 4000000001}}},
		Peers: []store.InterfaceRolePeerInput{{InterfaceRoleEvidenceClock: clock, SourceID: "peer-" + tenant, Address: netip.MustParseAddr("198.51.100.8"), ASN: 4294967295}}}
}

// Simulation of an owned store snapshot. Real RLS/current authority and served
// transport have separate integration roots; this never claims router proof.
func TestInterfaceRoleExplanationJoinsCompleteOwnedFactsAndPreservesOverride(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		for _, name := range []string{"transit", "customer", "rule", "ix", "override", "withdrawn", "withdrawn-override", "no-prefix", "ambiguous", "stale-binding"} {
			t.Run(tenant+"/"+name, func(t *testing.T) {
				in := roleExplanationFixture(tenant)
				ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
				want, reason := interfaceRoleTransit, "current_evidence"
				var ix []interfaceRoleIXPrefix
				switch name {
				case "customer":
					in.Policy.Definition.ProviderASNs = nil
					in.Policy.Definition.CustomerASNs = []uint32{4294967295}
					want = interfaceRoleCustomer
				case "rule":
					in.Policy.Definition.DescriptionRules = []entity.InterfaceRoleDescriptionRule{{ID: "55555555-5555-4555-8555-555555555555", Pattern: "^Transit", Role: interfaceRoleBackbone}}
					want, reason = interfaceRoleBackbone, "description_rule"
				case "ix":
					in.Policy.Definition.ProviderASNs = nil
					ix = []interfaceRoleIXPrefix{{SourceID: "peeringdb/ixpfx/7", Prefix: in.SNMP.Prefixes[0].Prefix, Clock: roleInputClock(in.SNMP.PrefixClock)}}
					want = interfaceRoleIX
				case "override", "withdrawn-override":
					in.Override = &entity.InterfaceRoleOverrideRecord{Scope: in.Scope, InterfaceID: in.InterfaceID, ID: "66666666-6666-4666-8666-666666666666", Revision: "9007199254740995", Role: interfaceRolePrivate}
					want, reason = interfaceRolePrivate, "operator_override"
					if name == "withdrawn-override" {
						in.SNMP, in.Peers = nil, nil
					}
				case "withdrawn":
					in.SNMP, in.Peers = nil, nil
					want, reason = interfaceRoleOther, "insufficient_evidence"
				case "no-prefix":
					in.SNMP.Prefixes = nil
					want, reason = interfaceRoleOther, "insufficient_evidence"
				case "ambiguous":
					in.SNMP.Prefixes = append(in.SNMP.Prefixes, entity.SNMPInterfacePrefix{IfIndex: 2, Prefix: netip.MustParsePrefix("198.51.100.0/25"), OnLink: true})
					other := in.SNMP.Bindings[0]
					other.IfIndex, other.InterfaceID = 2, "77777777-7777-4777-8777-777777777777"
					in.SNMP.Bindings = append(in.SNMP.Bindings, other)
					want, reason = interfaceRoleOther, "insufficient_evidence"
				case "stale-binding":
					in.SNMP.Bindings[0].ValidUntil = in.AsOf
					want, reason = interfaceRoleOther, "insufficient_evidence"
				}
				got, err := explainInterfaceRoleInputs(ctx, in, ix, interfaceRoleEvaluationBudget())
				if err != nil || got.Role != want || got.Reason != reason || got.Scope != in.Scope || got.InterfaceID != in.InterfaceID || got.Sources == nil {
					t.Fatal("role explanation lost owned complete association or override precedence", got, err)
				}
				if name == "transit" && (!got.SNMPCurrent || !got.PrefixCurrent || !slices.Contains(got.Sources, in.SNMP.PrefixSourceID) || !slices.Contains(got.Sources, in.Peers[0].SourceID) || !slices.Contains(got.Sources, in.SNMP.Bindings[0].SourceID)) {
					t.Fatal("role explanation lost contributing source provenance", got)
				}
			})
		}
	}
}

func TestInterfaceRoleExplanationRefusesForeignCanceledAndIncompleteAdmission(t *testing.T) {
	for _, name := range []string{"missing-tenant", "foreign-tenant", "foreign-policy", "foreign-override", "cancel", "memory", "work"} {
		t.Run(name, func(t *testing.T) {
			in := roleExplanationFixture("11111111-1111-4111-8111-111111111111")
			ctx, budget := tenancy.WithTenant(t.Context(), tenancy.ID(in.Scope.TenantID)), interfaceRoleEvaluationBudget()
			switch name {
			case "missing-tenant":
				ctx = t.Context()
			case "foreign-tenant":
				ctx = tenancy.WithTenant(t.Context(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
			case "foreign-policy":
				in.Policy.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			case "foreign-override":
				in.Override = &entity.InterfaceRoleOverrideRecord{Scope: entity.Scope{TenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ContextID: in.Scope.ContextID}, InterfaceID: in.InterfaceID}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "memory":
				budget.MemoryBytes = 4096
			case "work":
				budget.WorkUnits = 1
			}
			got, err := explainInterfaceRoleInputs(ctx, in, nil, budget)
			if err == nil || !reflect.DeepEqual(got, interfaceRoleExplanation{}) {
				t.Fatal("invalid role explanation returned a partial result", got, err)
			}
		})
	}
}

func TestInterfaceRolePeerAssociationSharesMultiPeerAdmission(t *testing.T) {
	ctx, scope, at, peer, snapshot, bindings := roleAssociationFixture("11111111-1111-4111-8111-111111111111")
	budget := interfaceRoleBudget{MemoryBytes: 1 << 20, WorkUnits: 12}
	first, err := associateInterfaceRolePeerAdmitted(ctx, scope, roleAssociationRouter, at, peer, snapshot, bindings, &budget)
	if err != nil || first.Peer.InterfaceID == "" || budget.WorkUnits >= 12 {
		t.Fatal("peer association reset shared operation admission", first, err)
	}
	second, err := associateInterfaceRolePeerAdmitted(ctx, scope, roleAssociationRouter, at, peer, snapshot, bindings, &budget)
	if !errors.Is(err, errInterfaceRoleBudget) || second.Peer.InterfaceID != "" {
		t.Fatal("multi-peer operation escaped cumulative admission", second, err)
	}
}

func TestInterfaceRolePublicationRejectsChangedOrWithdrawnContributors(t *testing.T) {
	for _, name := range []string{"unchanged", "time", "tenant", "parent", "index", "policy", "rules", "override", "snmp", "prefix", "prefix-withdrawal", "binding", "peer", "competing-peer"} {
		t.Run(name, func(t *testing.T) {
			before := roleExplanationFixture("11111111-1111-4111-8111-111111111111")
			raw, _ := json.Marshal(before)
			var after store.InterfaceRoleInputs
			if err := json.Unmarshal(raw, &after); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "time":
				after.AsOf = after.AsOf.Add(time.Second)
			case "tenant":
				after.Scope.TenantID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			case "parent":
				after.RouterID = after.InterfaceID
			case "index":
				after.IfIndex++
			case "policy":
				after.Policy.Revision = "9007199254740994"
			case "rules":
				after.Policy.Definition.DescriptionRules = []entity.InterfaceRoleDescriptionRule{{Pattern: ".*", Role: interfaceRolePrivate}}
			case "override":
				after.Override = &entity.InterfaceRoleOverrideRecord{Role: interfaceRoleCustomer}
			case "snmp":
				after.SNMP = nil
			case "prefix":
				after.SNMP.Prefixes[0].OnLink = false
			case "prefix-withdrawal":
				after.SNMP.Prefixes = nil
			case "binding":
				after.SNMP.Bindings[0].SourceID = "rebound"
			case "peer":
				after.Peers[0].ASN = 64497
			case "competing-peer":
				after.Peers = append(after.Peers, after.Peers[0])
			}
			if got, want := sameInterfaceRoleInputs(before, after), name == "unchanged" || name == "time"; got != want {
				t.Fatal("role publication accepted changed authority or rejected the same complete snapshot", name, got)
			}
		})
	}
}
