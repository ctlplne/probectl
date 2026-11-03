// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tags

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func TestCanonicalCIDRFactsConsiderEveryAddressAndWholePrefix(t *testing.T) {
	for _, kind := range []string{"device", "interface", "exporter", "agent", "test", "prefix"} {
		t.Run(kind, func(t *testing.T) {
			for _, family := range []struct{ wide, narrow, host, outside, inside string }{
				{"10.1.0.0/16", "10.1.2.0/24", "10.1.2.0/32", "192.0.2.1", "10.1.2.3"},
				{"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::/128", "2001:db9::1", "2001:db8:1::3"},
			} {
				scope := testScope()
				wide := Rule{Scope: scope, ID: ruleA, TagID: tagID, TargetKind: kind, Match: "cidr", AddressSide: kind, CIDR: family.wide, Value: "wide"}
				narrow := wide
				narrow.ID, narrow.CIDR, narrow.Value = ruleB, family.narrow, "narrow"
				snapshot, err := NewSnapshot(scope, 4, []Definition{testDefinition()}, nil, []Rule{wide, narrow})
				if err != nil {
					t.Fatal(err)
				}
				subject := Subject{Scope: scope, Kind: kind, ID: "owned-subject", AddressSide: kind}
				if kind == "prefix" {
					subject.Prefixes = []netip.Prefix{netip.MustParsePrefix(family.narrow)}
				} else {
					subject.Addresses = []netip.Addr{netip.MustParseAddr(family.outside), netip.MustParseAddr(family.inside), netip.MustParseAddr(family.inside)}
				}
				got, err := snapshot.ResolveContext(t.Context(), subject)
				if err != nil || len(got) != 1 || got[0].Value != "narrow" {
					t.Fatalf("complete %s facts lost strongest matching rule: %+v, %v", kind, got, err)
				}
				subject.TenantID = tenantB
				if got, err := snapshot.Resolve(subject); !errors.Is(err, ErrScopeMismatch) || got != nil {
					t.Fatal("fact set crossed tenant scope")
				}
				subject.Scope = scope
				if kind != "prefix" {
					subject.Addresses[0], subject.Addresses[1] = subject.Addresses[1], subject.Addresses[0]
					got, err := snapshot.Resolve(subject)
					if err != nil || len(got) != 1 || got[0].Value != "narrow" {
						t.Fatal("address order changed rule precedence")
					}
					subject.Addresses = []netip.Addr{netip.MustParseAddr(family.outside)}
					if got, err := snapshot.Resolve(subject); err != nil || len(got) != 0 {
						t.Fatal("uncovered address acquired a CIDR value")
					}
					continue
				}
				// A narrower rule (even on the range's base host) does not cover
				// the complete subject prefix. It cannot beat its enclosing rule.
				narrow.CIDR = family.host
				snapshot, err = NewSnapshot(scope, 5, []Definition{testDefinition()}, nil, []Rule{wide, narrow})
				if err != nil {
					t.Fatal(err)
				}
				got, err = snapshot.Resolve(subject)
				if err != nil || len(got) != 1 || got[0].Value != "wide" {
					t.Fatalf("representative host mislabeled a whole prefix: %+v, %v", got, err)
				}
				subject.Address = subject.Prefixes[0].Addr()
				if got, err := snapshot.Resolve(subject); !errors.Is(err, ErrInvalid) || got != nil {
					t.Fatal("prefix subject accepted a representative host")
				}
			}
		})
	}
}

type cancelOnTagCheck struct {
	context.Context
	cancel       context.CancelFunc
	calls, after int
}

func (c *cancelOnTagCheck) Err() error {
	c.calls++
	if c.calls == c.after {
		c.cancel()
	}
	return c.Context.Err()
}

func TestTagFactCompilationAndEvaluationCancelWithoutPartialResults(t *testing.T) {
	scope := testScope()
	rules := []Rule{
		{Scope: scope, ID: ruleA, TagID: tagID, TargetKind: "device", Match: "name_pattern", NamePattern: ".*", Value: "first"},
		{Scope: scope, ID: ruleB, TagID: tagID, TargetKind: "device", Match: "name_pattern", NamePattern: ".*", Value: "second"},
	}
	for _, stage := range []string{"compile", "evaluate"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			checked := &cancelOnTagCheck{Context: ctx, cancel: cancel, after: 4}
			if stage == "compile" {
				got, err := NewSnapshotContext(checked, scope, 1, []Definition{testDefinition()}, nil, rules)
				if !errors.Is(err, context.Canceled) || got != nil {
					t.Fatal("compilation published a partial snapshot after cancellation")
				}
				return
			}
			snapshot, err := NewSnapshot(scope, 1, []Definition{testDefinition()}, nil, rules)
			if err != nil {
				t.Fatal(err)
			}
			// Cancel after the first matching rule has selected a value.
			checked.after = 3
			got, err := snapshot.ResolveContext(checked, Subject{Scope: scope, Kind: "device", ID: "owned", Name: "edge"})
			if !errors.Is(err, context.Canceled) || got != nil || checked.calls != checked.after {
				t.Fatal("evaluation published partial tags or did not propagate cancellation")
			}
		})
	}
}

func TestTagNamePatternsUseAllAdmittedNames(t *testing.T) {
	rule := Rule{Scope: testScope(), ID: ruleA, TagID: tagID, TargetKind: "interface", Match: "name_pattern", NamePattern: "^Gig", Value: "uplink"}
	snapshot, err := NewSnapshot(testScope(), 1, []Definition{testDefinition()}, nil, []Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	subject := Subject{Scope: testScope(), Kind: "interface", ID: "owned", Name: "ifIndex 7", Names: []string{"other", "Gig0/7", "Gig0/7"}}
	got, err := snapshot.ResolveContext(t.Context(), subject)
	if err != nil || len(got) != 1 || got[0].Value != "uplink" {
		t.Fatal("current observed name could not match or duplicated a value")
	}
}
