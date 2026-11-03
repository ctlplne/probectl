// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/ctlplne/probectl/internal/tags"
)

func TestExplicitTagPrefixRejectsObservedRangeConflict(t *testing.T) {
	want := netip.MustParsePrefix("10.2.0.0/24")
	for _, observed := range [][]netip.Prefix{nil, {want}, {want, want}} {
		subject := tags.Subject{Kind: "prefix", Prefixes: observed}
		if err := applyExplicitTagNetwork(&subject, want.String()); err != nil || len(subject.Prefixes) != 1 || subject.Prefixes[0] != want {
			t.Fatal("matching explicit prefix lost its full range")
		}
	}
	for _, conflict := range []string{"10.2.0.0/25", "10.2.0.0/23", "10.9.0.0/24", "2001:db8::/32"} {
		before := []netip.Prefix{want, netip.MustParsePrefix(conflict)}
		subject := tags.Subject{Kind: "prefix", Prefixes: slices.Clone(before)}
		if err := applyExplicitTagNetwork(&subject, want.String()); !errors.Is(err, ErrTagSubjectFactsAmbiguous) {
			t.Fatal("contradictory observed range was silently replaced")
		}
		if !slices.Equal(subject.Prefixes, before) {
			t.Fatal("conflict applied a partial explicit fact")
		}
	}
	for _, subject := range []tags.Subject{{Kind: "device"}, {Kind: "agent"}} {
		if err := applyExplicitTagNetwork(&subject, want.String()); !errors.Is(err, tags.ErrInvalid) {
			t.Fatal("explicit range escaped the prefix kind")
		}
	}
	subject := tags.Subject{Kind: "prefix", Prefixes: []netip.Prefix{want}}
	if err := applyExplicitTagNetwork(&subject, "bad/24"); !errors.Is(err, tags.ErrInvalid) {
		t.Fatal("malformed explicit range became a fact")
	}
	if err := applyExplicitTagNetwork(&subject, ""); err != nil || !slices.Equal(subject.Prefixes, []netip.Prefix{want}) {
		t.Fatal("absent operator metadata erased an observation")
	}
}
