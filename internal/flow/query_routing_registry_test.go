// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRoutingRegistryKeepsCompletePathsUnknownASNsAndEveryQueryAxis(t *testing.T) {
	var names []string
	for _, side := range []string{"src", "dst"} {
		for _, suffix := range []string{"bgp_provenance", "bgp_prefix", "bgp_as_paths", "bgp_next_hop_as", "bgp_origin_as", "bgp_first_transit_as", "bgp_rpki"} {
			name := side + "_" + suffix
			field, ok := LookupQueryField(name)
			if !ok || field.Derived != "flow_routing" || !field.Raw || !field.Rollup || field.LegacyHourly {
				t.Fatal("complete routing field is absent from the shared query registry", name, field)
			}
			names = append(names, name)
		}
	}
	path, err := json.Marshal([]string{strings.Repeat("64500 ", 65_537) + "4294967295"})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)
	plan := QueryPlan{From: at.AddDate(-10, 0, 0), To: at, GroupBy: append([]string{"protocol"}, names[:7]...), MatrixWith: append([]string{"exporter"}, names[7:]...), View: "matrix", RowLimit: 50_000, Metrics: []QueryMetric{{Measure: "bps", Calculation: "p95", Role: "primary"}, {Measure: "bps", Calculation: "p99", Role: "secondary"}}, Filter: &QueryFilterGroup{Conditions: []QueryPredicate{{Field: "src_bgp_as_paths", Op: QueryEqual, Values: []string{string(path)}}}, Groups: []QueryFilterGroup{{Mode: "exclude", Conditions: []QueryPredicate{{Field: "dst_bgp_provenance", Op: QueryRegex, Values: []string{"^(unavailable|ambiguous)$"}}}}}}}
	got, err := NormalizeQueryPlan(plan, at)
	if err != nil || len(got.GroupBy) != 8 || len(got.MatrixWith) != 8 || got.RowLimit != 50_000 || got.Filter.Conditions[0].Values[0] != string(path) || !got.From.Equal(plan.From) {
		t.Fatal("routing plan lost complete path, matrix, percentile, rows or historical reach", err)
	}
	permissions := QueryPlanPermissions(got)
	slices.Sort(permissions)
	if !slices.Equal(permissions, []string{"entities.read", "events.read"}) {
		t.Fatal("registered routing plan omitted current source permissions", permissions)
	}
	for _, side := range []string{"src", "dst"} {
		for _, suffix := range []string{"bgp_next_hop_as", "bgp_origin_as", "bgp_first_transit_as"} {
			for _, op := range []QueryOperator{QueryEqual, QueryNotEqual, QueryIn, QueryNotIn} {
				values := []string{""}
				if op == QueryIn || op == QueryNotIn {
					values = append(values, "0", "4294967295")
				}
				filter, err := PrepareQueryFilter(&QueryFilterGroup{Conditions: []QueryPredicate{{Field: side + "_" + suffix, Op: op, Values: values}}})
				if err != nil {
					t.Fatal("unknown routing ASN cannot be selected independently of ASN zero", op, err)
				}
				for _, sample := range []string{"", "0", "1", "4294967295"} {
					want := slices.Contains(values, sample)
					if op == QueryNotEqual || op == QueryNotIn {
						want = !want
					}
					if filter.Matches(func(string) string { return sample }) != want {
						t.Fatal("routing ASN unknown/zero/full-width predicate changed meaning", op, sample)
					}
				}
			}
		}
	}
}
