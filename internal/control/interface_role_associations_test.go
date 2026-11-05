// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

const roleAssociationRouter = "44444444-4444-4444-8444-444444444444"

func roleAssociationFixture(tenant string) (context.Context, entity.Scope, time.Time, interfaceRoleUnboundPeer, interfaceRolePrefixSnapshot, []interfaceRoleInterfaceBinding) {
	facts, _, at := interfaceRoleFixture(tenant)
	peer := interfaceRoleUnboundPeer{Scope: facts.Scope, RouterID: roleAssociationRouter, SourceID: "peer-" + tenant,
		Address: netip.MustParseAddr("198.51.100.8"), ASN: 64496, SourceActive: true, Clock: facts.Clock}
	snapshot := interfaceRolePrefixSnapshot{Scope: facts.Scope, RouterID: roleAssociationRouter, SourceID: "prefix-" + tenant,
		SourceActive: true, Complete: true, Clock: facts.Clock, Rows: []interfaceRolePrefixRow{
			{IfIndex: 4_000_000_001, Prefix: netip.MustParsePrefix("198.51.100.0/24"), OnLink: true},
			{IfIndex: 4_000_000_001, Prefix: netip.MustParsePrefix("198.51.100.0/25"), OnLink: true},
		}}
	bindings := []interfaceRoleInterfaceBinding{{Scope: facts.Scope, RouterID: roleAssociationRouter, InterfaceID: facts.InterfaceID,
		SourceID: "binding-" + tenant, IfIndex: 4_000_000_001, SourceActive: true, Clock: facts.Clock}}
	return tenancy.WithTenant(context.Background(), tenancy.ID(tenant)), facts.Scope, at, peer, snapshot, bindings
}

// Component fixtures only: real source/cert/RLS/parent loading remains required.
func TestInterfaceRolePeerAssociationUsesOwnedRouterAndCompletePrefixes(t *testing.T) {
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		for _, family := range []string{"IPv4", "IPv6"} {
			t.Run(tenant+"/"+family, func(t *testing.T) {
				ctx, scope, at, peer, snapshot, bindings := roleAssociationFixture(tenant)
				if family == "IPv6" {
					peer.Address = netip.MustParseAddr("2001:db8:1::8")
					snapshot.Rows[0].Prefix = netip.MustParsePrefix("2001:db8:1::/64")
					snapshot.Rows[1].Prefix = netip.MustParsePrefix("2001:db8:1::/80")
				}
				snapshot.Clock.ValidUntil = at.Add(20 * time.Second)
				bindings[0].Clock.ObservedAt = at.Add(-10 * time.Second)
				got, err := associateInterfaceRolePeer(ctx, scope, roleAssociationRouter, at, peer, snapshot, bindings, interfaceRoleTestBudget())
				if err != nil || got.Reason != "unique_current_prefix" || got.Peer.InterfaceID != bindings[0].InterfaceID ||
					got.Peer.Scope != scope || got.Peer.SourceID != peer.SourceID || got.Peer.ASN != peer.ASN || !got.Peer.SourceActive ||
					!got.Peer.Clock.ValidUntil.Equal(snapshot.Clock.ValidUntil) || !got.Peer.Clock.ObservedAt.Equal(bindings[0].Clock.ObservedAt) {
					t.Fatal("owned complete router association changed identity or extended source lifetime", got, err)
				}
				facts, policy, _ := interfaceRoleFixture(tenant)
				facts.Peers = []interfaceRolePeer{got.Peer}
				decision, err := classifyInterfaceRole(ctx, scope, at, facts, policy, nil, interfaceRoleTestBudget())
				if err != nil || decision.Role != interfaceRoleTransit || len(decision.Sources) != 5 ||
					!slices.Contains(decision.Sources, snapshot.SourceID) || !slices.Contains(decision.Sources, bindings[0].SourceID) ||
					!slices.Contains(decision.Sources, peer.SourceID) || !slices.Contains(decision.Sources, facts.SourceID) ||
					!slices.Contains(decision.Sources, policy.Declarations[0].SourceID) {
					t.Fatal("associated role explanation lost its current contributing sources", decision, err)
				}
			})
		}
	}
}

func TestInterfaceRolePeerAssociationRefusesForeignAndMalformedSnapshots(t *testing.T) {
	for _, name := range []string{"missing-tenant", "peer-tenant", "prefix-context", "binding-tenant", "peer-router", "prefix-router", "binding-router", "invalid-router", "invalid-interface", "duplicate-index", "duplicate-entity", "duplicate-prefix", "host-bits", "mapped-prefix", "zero-index", "source", "clock", "zero-asn", "mapped-peer"} {
		t.Run(name, func(t *testing.T) {
			ctx, scope, at, peer, snapshot, bindings := roleAssociationFixture("11111111-1111-4111-8111-111111111111")
			router, expected := roleAssociationRouter, errInterfaceRoleInput
			switch name {
			case "missing-tenant":
				ctx, expected = context.Background(), entity.ErrScopeMismatch
			case "peer-tenant":
				peer.Scope.TenantID, expected = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", entity.ErrScopeMismatch
			case "prefix-context":
				snapshot.Scope.ContextID, expected = "55555555-5555-4555-8555-555555555555", entity.ErrScopeMismatch
			case "binding-tenant":
				bindings[0].Scope.TenantID, expected = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", entity.ErrScopeMismatch
			case "peer-router":
				peer.RouterID, expected = scope.ContextID, entity.ErrScopeMismatch
			case "prefix-router":
				snapshot.RouterID, expected = scope.ContextID, entity.ErrScopeMismatch
			case "binding-router":
				bindings[0].RouterID, expected = scope.ContextID, entity.ErrScopeMismatch
			case "invalid-router":
				router = "not-a-canonical-router"
				peer.RouterID, snapshot.RouterID = router, router
			case "invalid-interface":
				bindings[0].InterfaceID = "not-an-interface"
			case "duplicate-index", "duplicate-entity":
				other := bindings[0]
				if name == "duplicate-index" {
					other.InterfaceID = scope.ContextID
				} else {
					other.IfIndex++
				}
				bindings = append(bindings, other)
			case "duplicate-prefix":
				snapshot.Rows = append(snapshot.Rows, snapshot.Rows[0])
			case "host-bits":
				snapshot.Rows[1].Prefix = netip.MustParsePrefix("198.51.100.1/24")
			case "mapped-prefix":
				snapshot.Rows[1].Prefix = netip.MustParsePrefix("::ffff:192.0.2.0/120")
			case "zero-index":
				snapshot.Rows[1].IfIndex = 0
			case "source":
				bindings[0].SourceID = " source-with-padding"
			case "clock":
				snapshot.Clock.ValidUntil = snapshot.Clock.ObservedAt
			case "zero-asn":
				peer.ASN = 0
			case "mapped-peer":
				peer.Address = netip.MustParseAddr("::ffff:198.51.100.8")
			}
			got, err := associateInterfaceRolePeer(ctx, scope, router, at, peer, snapshot, bindings, interfaceRoleTestBudget())
			if !errors.Is(err, expected) || got.Peer.InterfaceID != "" || len(got.Peer.AssociationSources) != 0 {
				t.Fatal("foreign or malformed association returned identity or partial provenance", name, got, err)
			}
		})
	}
}

func TestInterfaceRolePeerAssociationKeepsAmbiguousAndUnavailableEvidenceUnresolved(t *testing.T) {
	for _, name := range []string{"incomplete", "inactive-prefix", "inactive-peer", "stale-prefix", "stale-peer", "inactive-binding", "stale-binding", "unknown-index", "overlap", "default", "off-link", "outside", "link-local", "zoned"} {
		t.Run(name, func(t *testing.T) {
			ctx, scope, at, peer, snapshot, bindings := roleAssociationFixture("11111111-1111-4111-8111-111111111111")
			switch name {
			case "incomplete":
				snapshot.Complete = false
			case "inactive-prefix":
				snapshot.SourceActive = false
			case "inactive-peer":
				peer.SourceActive = false
			case "stale-prefix":
				snapshot.Clock.ValidUntil = at
			case "stale-peer":
				peer.Clock.ValidUntil = at
			case "inactive-binding":
				bindings[0].SourceActive = false
			case "stale-binding":
				bindings[0].Clock.ValidUntil = at
			case "unknown-index", "overlap":
				snapshot.Rows[1].IfIndex++
				if name == "overlap" {
					other := bindings[0]
					other.IfIndex, other.InterfaceID = snapshot.Rows[1].IfIndex, scope.ContextID
					bindings = append(bindings, other)
				}
			case "default":
				snapshot.Rows = []interfaceRolePrefixRow{{IfIndex: bindings[0].IfIndex, Prefix: netip.MustParsePrefix("0.0.0.0/0"), OnLink: true}}
			case "off-link":
				for i := range snapshot.Rows {
					snapshot.Rows[i].OnLink = false
				}
			case "outside":
				peer.Address = netip.MustParseAddr("203.0.113.8")
			case "link-local":
				peer.Address = netip.MustParseAddr("fe80::8")
			case "zoned":
				peer.Address = netip.MustParseAddr("fe80::8%eth0")
			}
			got, err := associateInterfaceRolePeer(ctx, scope, roleAssociationRouter, at, peer, snapshot, bindings, interfaceRoleTestBudget())
			if err != nil || got.Reason == "" || got.Peer.InterfaceID != "" || got.Peer.ASN != 0 || got.Peer.SourceID != "" || len(got.Peer.AssociationSources) != 0 {
				t.Fatal("unavailable or ambiguous association inferred a canonical peer", name, got, err)
			}
			if name == "overlap" && got.Reason != "ambiguous_prefix" {
				t.Fatal("overlapping interfaces chose a longest-prefix winner", got)
			}
		})
	}
}

type roleAssociationCancelContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *roleAssociationCancelContext) Err() error {
	c.checks--
	if c.checks <= 0 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestInterfaceRolePeerAssociationPreservesProvenanceBudgetsAndCancellation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ctx, scope, at, peer, snapshot, bindings := roleAssociationFixture("11111111-1111-4111-8111-111111111111")
		got, err := associateInterfaceRolePeer(ctx, scope, roleAssociationRouter, at, peer, snapshot, bindings, interfaceRoleTestBudget())
		if err != nil || len(got.Peer.AssociationSources) != 2 || !slices.Contains(got.Peer.AssociationSources, snapshot.SourceID) || !slices.Contains(got.Peer.AssociationSources, bindings[0].SourceID) {
			t.Fatal("peer association provenance omitted current prefix", got, err)
		}
		got.Peer.AssociationSources[0] = "mutated-output"
		fresh, err := associateInterfaceRolePeer(ctx, scope, roleAssociationRouter, at, peer, snapshot, bindings, interfaceRoleTestBudget())
		if err != nil || slices.Contains(fresh.Peer.AssociationSources, "mutated-output") {
			t.Fatal("caller mutation corrupted later association provenance", fresh, err)
		}
		facts, policy, _ := interfaceRoleFixture(scope.TenantID)
		facts.Peers = []interfaceRolePeer{fresh.Peer}
		facts.Peers[0].AssociationSources = []string{" invalid-source"}
		if result, err := classifyInterfaceRole(ctx, scope, at, facts, policy, nil, interfaceRoleTestBudget()); !errors.Is(err, errInterfaceRoleInput) || len(result.Sources) != 0 {
			t.Fatal("classifier accepted invalid association provenance", result, err)
		}
		facts.Peers[0] = fresh.Peer
		budget := interfaceRoleTestBudget()
		budget.MemoryBytes = 6000
		if result, err := classifyInterfaceRole(ctx, scope, at, facts, policy, nil, budget); !errors.Is(err, errInterfaceRoleBudget) || len(result.Sources) != 0 {
			t.Fatal("classifier retained uncharged association provenance", result, err)
		}
	})
	for _, phase := range []string{"memory", "work", "before", "during"} {
		t.Run(phase, func(t *testing.T) {
			ctx, scope, at, peer, snapshot, bindings := roleAssociationFixture("11111111-1111-4111-8111-111111111111")
			budget, expected := interfaceRoleTestBudget(), errInterfaceRoleBudget
			switch phase {
			case "memory":
				budget.MemoryBytes = 4096
			case "work":
				budget.WorkUnits = 1
			case "before", "during":
				base, cancel := context.WithCancel(ctx)
				defer cancel()
				if phase == "before" {
					cancel()
					ctx = base
				} else {
					ctx = &roleAssociationCancelContext{Context: base, cancel: cancel, checks: 9}
				}
				expected = context.Canceled
			}
			got, err := associateInterfaceRolePeer(ctx, scope, roleAssociationRouter, at, peer, snapshot, bindings, budget)
			if !errors.Is(err, expected) || got.Peer.InterfaceID != "" || len(got.Peer.AssociationSources) != 0 {
				t.Fatal("association returned partial evidence after cancellation or exhausted budget", phase, got, err)
			}
		})
	}
}
