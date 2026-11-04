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
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func interfaceRoleFixture(tenant string) (interfaceRoleFacts, interfaceRolePolicy, time.Time) {
	at := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	scope := entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}
	clock := interfaceRoleClock{ObservedAt: at.Add(-time.Minute), ValidUntil: at.Add(time.Minute)}
	id := "33333333-3333-4333-8333-333333333333"
	facts := interfaceRoleFacts{Scope: scope, InterfaceID: id, SourceID: "fact-" + tenant, Clock: clock, Addresses: []netip.Addr{netip.MustParseAddr("198.51.100.7")}, Peers: []interfaceRolePeer{{Scope: scope, InterfaceID: id, SourceID: "peer-" + tenant, ASN: 64496, Active: true, Clock: clock}}}
	policy := interfaceRolePolicy{Scope: scope, OwnASN: 64500, OwnASNSourceID: "own-as-" + tenant, Declarations: []interfaceRoleDeclaration{{Scope: scope, ASN: 64496, Role: interfaceRoleTransit, SourceID: "provider-" + tenant}}}
	return facts, policy, at
}
func interfaceRoleTestBudget() interfaceRoleBudget {
	return interfaceRoleBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
}

// Pure component proof only: inputs stand for an eventual verified RLS/source
// snapshot. This does not prove producer sessions, storage or public surfaces.
func TestInterfaceRoleClassificationKeepsOwnedEvidenceAndOverrides(t *testing.T) {
	tenants := []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"}
	for lane, tenant := range tenants {
		t.Run(tenant, func(t *testing.T) {
			for _, name := range []string{"transit", "customer", "backbone", "private-rule", "ix", "ix-ipv6", "outside-ix", "conflict", "unknown-external", "inactive", "stale-peer", "stale-facts", "ordered-rule", "override", "stale-override"} {
				t.Run(name, func(t *testing.T) {
					facts, policy, at := interfaceRoleFixture(tenant)
					expected, reason := interfaceRoleTransit, "current_evidence"
					var prefixes []interfaceRoleIXPrefix
					rule := interfaceRoleRuleMatch{Scope: facts.Scope, InterfaceID: facts.InterfaceID, RuleID: "rule-" + tenant, FactSourceID: facts.SourceID, Role: interfaceRolePrivate, Matched: true}
					ix := interfaceRoleIXPrefix{SourceID: "shared-ix-prefix", Prefix: netip.MustParsePrefix("198.51.100.0/24"), Clock: facts.Clock}
					switch name {
					case "customer":
						policy.Declarations[0].Role = interfaceRoleCustomer
						expected = interfaceRoleCustomer
					case "backbone":
						facts.Peers[0].ASN = policy.OwnASN
						facts.Peers[0].Internal = true
						expected = interfaceRoleBackbone
					case "private-rule":
						policy.Rules = []interfaceRoleRuleMatch{rule}
						expected, reason = interfaceRolePrivate, "description_rule"
					case "ix":
						policy.Declarations = nil
						prefixes = []interfaceRoleIXPrefix{ix}
						expected = interfaceRoleIX
					case "ix-ipv6":
						policy.Declarations = nil
						facts.Addresses = []netip.Addr{netip.MustParseAddr("2001:db8:1::ffff")}
						ix.Prefix = netip.MustParsePrefix("2001:db8:1::/64")
						prefixes = []interfaceRoleIXPrefix{ix}
						expected = interfaceRoleIX
					case "outside-ix":
						policy.Declarations = nil
						facts.Addresses = []netip.Addr{netip.MustParseAddr("198.51.101.0")}
						prefixes = []interfaceRoleIXPrefix{ix}
						expected, reason = interfaceRoleOther, "insufficient_evidence"
					case "conflict":
						prefixes = []interfaceRoleIXPrefix{ix}
						expected, reason = interfaceRoleOther, "conflicting_evidence"
					case "unknown-external":
						policy.Declarations = nil
						expected, reason = interfaceRoleOther, "insufficient_evidence"
					case "inactive":
						facts.Peers[0].Active = false
						expected, reason = interfaceRoleOther, "insufficient_evidence"
					case "stale-peer":
						facts.Peers[0].Clock.ValidUntil = at.Add(-time.Second)
						expected, reason = interfaceRoleOther, "insufficient_evidence"
					case "stale-facts":
						facts.Clock.ValidUntil = at.Add(-time.Second)
						expected, reason = interfaceRoleOther, "insufficient_evidence"
					case "ordered-rule":
						second := rule
						second.RuleID = "a-second-rule"
						second.Role = interfaceRoleCustomer
						rule.RuleID = "z-first-rule"
						policy.Rules = []interfaceRoleRuleMatch{rule, second}
						expected, reason = interfaceRolePrivate, "description_rule"
					case "override", "stale-override":
						prefixes = []interfaceRoleIXPrefix{ix}
						policy.Rules = []interfaceRoleRuleMatch{rule}
						policy.Override = &interfaceRoleOverride{Scope: facts.Scope, InterfaceID: facts.InterfaceID, SourceID: "override-" + tenant, Role: interfaceRoleCustomer}
						expected, reason = interfaceRoleCustomer, "operator_override"
						if name == "stale-override" {
							facts.Clock.ValidUntil = at.Add(-time.Second)
						}
					}
					ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
					got, err := classifyInterfaceRole(ctx, facts.Scope, at, facts, policy, prefixes, interfaceRoleTestBudget())
					if err != nil || got.Scope != facts.Scope || got.InterfaceID != facts.InterfaceID || got.Role != expected || got.Reason != reason || !got.AsOf.Equal(at) {
						t.Fatal("owned role/source decision changed", name, got, err)
					}
					if strings.Contains(strings.Join(got.Sources, ","), tenants[1-lane]) {
						t.Fatal("role provenance contains foreign tenant evidence")
					}
					if expected != interfaceRoleOther && len(got.Sources) == 0 {
						t.Fatal("classified role has no provenance")
					}
				})
			}
		})
	}
}

func TestInterfaceRoleClassifierRefusesForeignMalformedAndOverBudgetFacts(t *testing.T) {
	tenant := "11111111-1111-4111-8111-111111111111"
	foreign := entity.Scope{TenantID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", ContextID: "22222222-2222-4222-8222-222222222222"}
	cases := map[string]func(*interfaceRoleFacts, *interfaceRolePolicy, *[]interfaceRoleIXPrefix){
		"facts-tenant":  func(f *interfaceRoleFacts, _ *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) { f.Scope = foreign },
		"policy-tenant": func(_ *interfaceRoleFacts, p *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) { p.Scope = foreign },
		"peer-tenant": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			f.Peers[0].Scope = foreign
		},
		"peer-interface": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			f.Peers[0].InterfaceID = "another-interface"
		},
		"declaration-tenant": func(_ *interfaceRoleFacts, p *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			p.Declarations[0].Scope = foreign
		},
		"overlap": func(_ *interfaceRoleFacts, p *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			d := p.Declarations[0]
			d.Role = interfaceRoleCustomer
			p.Declarations = append(p.Declarations, d)
		},
		"own-as-provider": func(_ *interfaceRoleFacts, p *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			p.Declarations[0].ASN = p.OwnASN
		},
		"zero-as": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) { f.Peers[0].ASN = 0 },
		"invalid-interface": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			f.InterfaceID = "raw-ifindex:7"
		},
		"invalid-source": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			f.SourceID = "bad\nsource"
		},
		"blank-source": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			f.SourceID = " "
		},
		"padded-source": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			f.SourceID = " padded-source "
		},
		"invalid-clock": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			f.Clock.ValidUntil = f.Clock.ObservedAt
		},
		"invalid-address": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			f.Addresses = []netip.Addr{netip.MustParseAddr("ff02::1")}
		},
		"rule-tenant": func(f *interfaceRoleFacts, p *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			p.Rules = []interfaceRoleRuleMatch{{Scope: foreign, InterfaceID: f.InterfaceID, FactSourceID: f.SourceID, RuleID: "rule", Role: interfaceRolePrivate, Matched: true}}
		},
		"rule-fact": func(f *interfaceRoleFacts, p *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			p.Rules = []interfaceRoleRuleMatch{{Scope: f.Scope, InterfaceID: f.InterfaceID, FactSourceID: "another-fact", RuleID: "rule", Role: interfaceRolePrivate, Matched: true}}
		},
		"override-tenant": func(f *interfaceRoleFacts, p *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			p.Override = &interfaceRoleOverride{Scope: foreign, InterfaceID: f.InterfaceID, SourceID: "override", Role: interfaceRoleCustomer}
		},
		"override-role": func(f *interfaceRoleFacts, p *interfaceRolePolicy, _ *[]interfaceRoleIXPrefix) {
			p.Override = &interfaceRoleOverride{Scope: f.Scope, InterfaceID: f.InterfaceID, SourceID: "override", Role: "invented"}
		},
		"prefix-host-bits": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, p *[]interfaceRoleIXPrefix) {
			*p = []interfaceRoleIXPrefix{{SourceID: "ix", Prefix: netip.MustParsePrefix("198.51.100.7/24"), Clock: f.Clock}}
		},
		"wildcard-prefix": func(f *interfaceRoleFacts, _ *interfaceRolePolicy, p *[]interfaceRoleIXPrefix) {
			*p = []interfaceRoleIXPrefix{{SourceID: "ix", Prefix: netip.MustParsePrefix("0.0.0.0/0"), Clock: f.Clock}}
		},
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f, p, at := interfaceRoleFixture(tenant)
			var prefixes []interfaceRoleIXPrefix
			edit(&f, &p, &prefixes)
			got, err := classifyInterfaceRole(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), entity.Scope{TenantID: tenant, ContextID: "22222222-2222-4222-8222-222222222222"}, at, f, p, prefixes, interfaceRoleTestBudget())
			if err == nil || !reflect.DeepEqual(got, interfaceRoleDecision{}) {
				t.Fatal("invalid role evidence returned a partial or foreign decision", got, err)
			}
		})
	}
	f, p, at := interfaceRoleFixture(tenant)
	for _, ctx := range []context.Context{t.Context(), tenancy.WithTenant(t.Context(), tenancy.ID(foreign.TenantID))} {
		if got, err := classifyInterfaceRole(ctx, f.Scope, at, f, p, nil, interfaceRoleTestBudget()); err == nil || !reflect.DeepEqual(got, interfaceRoleDecision{}) {
			t.Fatal("missing/mismatched context returned a role")
		}
	}
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	for _, budget := range []interfaceRoleBudget{{}, {MemoryBytes: 4095, WorkUnits: 10000}, {MemoryBytes: 1 << 20, WorkUnits: 1}} {
		if got, err := classifyInterfaceRole(ctx, f.Scope, at, f, p, nil, budget); !errors.Is(err, errInterfaceRoleBudget) || !reflect.DeepEqual(got, interfaceRoleDecision{}) {
			t.Fatal("missing or exhausted cost policy returned a role", err)
		}
	}
	success := false
	for work := int64(1); work < 2048; work++ {
		got, err := classifyInterfaceRole(ctx, f.Scope, at, f, p, nil, interfaceRoleBudget{MemoryBytes: 1 << 20, WorkUnits: work})
		if err != nil {
			if !errors.Is(err, errInterfaceRoleBudget) || !reflect.DeepEqual(got, interfaceRoleDecision{}) {
				t.Fatal("late budget refusal returned partial provenance", err)
			}
			continue
		}
		if got.Role != interfaceRoleTransit {
			t.Fatal("budget changed classification")
		}
		success = true
		break
	}
	if !success {
		t.Fatal("bounded positive role case never completed")
	}
}

func TestInterfaceRoleClassifierKeepsCompleteStableProvenanceAndCancellation(t *testing.T) {
	f, p, at := interfaceRoleFixture("11111111-1111-4111-8111-111111111111")
	peer := f.Peers[0]
	peer.SourceID = "a-second-peer"
	f.Peers = append(f.Peers, peer)
	declaration := p.Declarations[0]
	declaration.SourceID = "a-second-declaration"
	p.Declarations = append(p.Declarations, declaration)
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(f.Scope.TenantID))
	first, err := classifyInterfaceRole(ctx, f.Scope, at, f, p, nil, interfaceRoleTestBudget())
	if err != nil || len(first.Sources) != 4 {
		t.Fatal("role provenance omitted matching current evidence", first, err)
	}
	slices.Reverse(f.Peers)
	slices.Reverse(p.Declarations)
	second, err := classifyInterfaceRole(ctx, f.Scope, at, f, p, nil, interfaceRoleTestBudget())
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("role depends on input map/order", err)
	}
	first.Sources[0] = "mutated-result"
	third, err := classifyInterfaceRole(ctx, f.Scope, at, f, p, nil, interfaceRoleTestBudget())
	if err != nil || !reflect.DeepEqual(second, third) {
		t.Fatal("caller mutation escaped request-owned provenance", err)
	}
	for check := 1; check < 40; check++ {
		parent, cancel := context.WithCancel(ctx)
		guarded := &interfaceRoleCancelContext{Context: parent, cancel: cancel, at: check}
		got, err := classifyInterfaceRole(guarded, f.Scope, at, f, p, nil, interfaceRoleTestBudget())
		cancel()
		if err != nil && (!errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, interfaceRoleDecision{})) {
			t.Fatal("cancellation returned partial role provenance", got, err)
		}
	}
}

type interfaceRoleCancelContext struct {
	context.Context
	cancel     context.CancelFunc
	checks, at int
}

func (c *interfaceRoleCancelContext) Err() error {
	c.checks++
	if c.checks >= c.at {
		c.cancel()
	}
	return c.Context.Err()
}
