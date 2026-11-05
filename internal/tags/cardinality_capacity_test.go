// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package tags

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
)

func TestSnapshotRetainsMetadataAboveFormerCountCeilings(t *testing.T) {
	scope := testScope()
	definitions := make([]Definition, 129)
	for i := range definitions {
		definitions[i] = Definition{TenantID: scope.TenantID, ID: fmt.Sprintf("10000000-0000-4000-8000-%012d", i+1), Key: fmt.Sprintf("custom_%03d", i)}
	}
	const records = 50001
	assignments, rules := make([]Assignment, records), make([]Rule, records)
	lastTag := definitions[len(definitions)-1].ID
	for i := range assignments {
		assignments[i] = Assignment{Scope: scope, TagID: lastTag, TargetKind: "exporter", TargetID: fmt.Sprintf("exporter-%d", i), Value: "last-reviewed-binding", Source: "manual"}
		address := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		rules[i] = Rule{Scope: scope, ID: fmt.Sprintf("20000000-0000-4000-8000-%012d", i+1), TagID: lastTag, TargetKind: "exporter", Match: "cidr", AddressSide: "exporter", CIDR: netip.PrefixFrom(address, 32).String(), Value: "last-rule"}
	}
	for _, part := range []string{"assignments", "rules"} {
		t.Run(part, func(t *testing.T) {
			var selectedAssignments []Assignment
			var selectedRules []Rule
			subject := testSubject()
			if part == "assignments" {
				selectedAssignments = assignments
				subject.ID = assignments[records-1].TargetID
			} else {
				selectedRules = rules
				subject.Address = netip.MustParsePrefix(rules[records-1].CIDR).Addr()
			}
			snapshot, err := NewSnapshotContext(t.Context(), scope, 11, definitions, selectedAssignments, selectedRules)
			if err != nil {
				t.Fatal("above-former metadata count refused", err)
			}
			got, err := snapshot.ResolveContext(t.Context(), subject)
			want := "last-reviewed-binding"
			if part == "rules" {
				want = "last-rule"
			}
			if err != nil || len(got) != 1 || got[0].TagID != lastTag || got[0].Value != want {
				t.Fatal("above-former metadata was truncated", got, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if snapshot, err := NewSnapshotContext(ctx, scope, 11, definitions, assignments, rules); snapshot != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("larger metadata ignored cancellation", err)
	}
}
