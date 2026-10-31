// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"strings"
	"testing"
	"time"
)

func TestQueryD103FilterCompositionAndPublishedGroupDepth(t *testing.T) {
	predicates := make([]QueryPredicate, 250)
	for i := range predicates {
		predicates[i] = QueryPredicate{Field: "dst_port", Op: QueryEqual, Values: []string{"443"}}
	}
	input := &QueryFilterGroup{Match: "OR", Groups: []QueryFilterGroup{{Match: "AND", Mode: "exclude", Conditions: predicates}}}
	got, err := NormalizeQueryFilterGroup(input)
	if err != nil || got.Match != "any" || got.Groups[0].Match != "all" || got.Groups[0].Mode != "exclude" || len(got.Groups[0].Conditions) != 250 {
		t.Fatalf("published250-per-group reach rejected: %+v %v", got, err)
	}
	predicates[0].Values[0] = "80"
	if got.Groups[0].Conditions[0].Values[0] != "443" {
		t.Fatal("validated tree shares input value slices")
	}
	tooWide := &QueryFilterGroup{Conditions: append(predicates, predicates[0])}
	if _, err := NormalizeQueryFilterGroup(tooWide); err == nil {
		t.Fatal("group structural bound ignored")
	}
	group := QueryFilterGroup{Conditions: []QueryPredicate{{Field: "src_asn", Op: QueryGreater, Values: []string{"64512"}}}}
	for i := 1; i < 5; i++ {
		group = QueryFilterGroup{Groups: []QueryFilterGroup{group}}
	}
	if _, err := NormalizeQueryFilterGroup(&group); err != nil {
		t.Fatalf("depth five rejected: %v", err)
	}
	group = QueryFilterGroup{Groups: []QueryFilterGroup{group}}
	if _, err := NormalizeQueryFilterGroup(&group); err == nil {
		t.Fatal("depth six accepted")
	}
	if _, err := NormalizeQueryFilterGroup(&QueryFilterGroup{}); err == nil {
		t.Fatal("empty nested group has ambiguous meaning")
	}
	if _, err := NormalizeQueryFilterGroup(&QueryFilterGroup{Conditions: []QueryPredicate{{Field: "tenant_id", Op: QueryEqual, Values: []string{"foreign"}}}}); err == nil {
		t.Fatal("tenant filter entered nested grammar")
	}
}

func TestQueryD102OperatorsAndRE2Bounds(t *testing.T) {
	valid := []QueryPredicate{
		{Field: "src_as_name", Op: QueryContains, Values: []string{"Mixed Case"}},
		{Field: "dst_as_name", Op: QueryNotContains, Values: []string{"Transit"}},
		{Field: "src_addr", Op: QueryRegex, Values: []string{`^192\.0\.2\.`}},
		{Field: "src_as_name", Op: QueryNotRegex, Values: []string{strings.Repeat("a", 1024)}},
		{Field: "raw_bytes", Op: QueryGreater, Values: []string{"18446744073709551614"}},
		{Field: "dst_port", Op: QueryLess, Values: []string{"1024"}},
		{Field: "tcp_flags", Op: QueryBitAnd, Values: []string{"18"}},
		{Field: "tcp_flag_names", Op: QueryBitAnd, Values: []string{"18"}},
	}
	if _, err := NormalizeQueryPredicates(valid); err != nil {
		t.Fatal(err)
	}
	for _, pattern := range []string{strings.Repeat("a", 1025), `(?=backtracking)`, `(a)\1`} {
		if _, err := NormalizeQueryPredicates([]QueryPredicate{{Field: "src_as_name", Op: QueryRegex, Values: []string{pattern}}}); err == nil {
			t.Fatalf("oversized/unsupported RE2 pattern accepted")
		}
	}
	for _, predicate := range []QueryPredicate{
		{Field: "src_port", Op: QueryContains, Values: []string{"44"}},
		{Field: "src_as_name", Op: QueryGreater, Values: []string{"A"}},
		{Field: "tcp_flags", Op: QueryBitAnd, Values: []string{"256"}},
	} {
		if _, err := NormalizeQueryPredicates([]QueryPredicate{predicate}); err == nil {
			t.Fatalf("invalid typed operator accepted: %+v", predicate)
		}
	}
}

func TestQueryD102MetricFamiliesStatisticsAndRoles(t *testing.T) {
	definitions := QueryMetricDefinitions()
	seen := map[string]bool{}
	selections := []QueryMetric{}
	for _, definition := range definitions {
		seen[definition.Name] = true
		for _, calculation := range definition.Calculations {
			role := "additional"
			if len(selections) == 0 {
				role = "primary"
			}
			selections = append(selections, QueryMetric{Measure: definition.Name, Calculation: calculation, Role: role})
		}
	}
	for _, name := range []string{"bps", "pps", "fps", "bytes", "packets", "unique_src", "unique_dst", "unique_src_port", "unique_dst_port", "unique_src_asn", "unique_dst_asn", "unique_src_country", "unique_dst_country"} {
		if !seen[name] {
			t.Errorf("missing required metric family %s", name)
		}
	}
	if _, err := NormalizeQueryMetrics(selections); err != nil {
		t.Fatalf("registered table calculations capped below reach: %v", err)
	}
	chart := []QueryMetric{{Measure: "bps", Calculation: "p95", Role: "primary"}, {Measure: "pps", Calculation: "p99", Role: "secondary"}, {Measure: "fps", Calculation: "max", Role: "secondary"}, {Measure: "unique_src_port", Calculation: "total", Role: "secondary"}}
	if _, err := NormalizeQueryMetrics(chart); err != nil {
		t.Fatalf("one primary plus three secondary rejected: %v", err)
	}
	chart = append(chart, QueryMetric{Measure: "unique_dst_country", Calculation: "avg", Role: "secondary"})
	if _, err := NormalizeQueryMetrics(chart); err == nil {
		t.Fatal("fourth secondary chart metric accepted")
	}
}

func TestQueryD102PlanPublishedReachAndRetentionRange(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	eight := []string{"src_addr", "dst_addr", "src_port", "dst_port", "src_asn", "dst_asn", "src_country", "dst_country"}
	plan := QueryPlan{From: now.AddDate(-3, 0, 0), To: now, GroupBy: eight, View: "table", RowLimit: 50000, PageSize: 5000, BucketSeconds: 604800, SeriesDepth: 40}
	got, err := NormalizeQueryPlan(plan, now)
	if err != nil || len(got.GroupBy) != 8 || got.RowLimit != 50000 || !got.From.Equal(plan.From) {
		t.Fatalf("D102 reach reduced by small caps: %+v %v", got, err)
	}
	plan.View = "matrix"
	plan.MatrixWith = eight
	plan.RowLimit = 350
	plan.PageSize = 350
	plan.MatrixDepth = 15
	if got, err := NormalizeQueryPlan(plan, now); err != nil || len(got.MatrixWith) != 8 || got.MatrixDepth != 15 {
		t.Fatalf("8x8 dimension matrix /15-axis values rejected: %+v %v", got, err)
	}
	for _, bucket := range []int{59, 604801} {
		plan.BucketSeconds = bucket
		if _, err := NormalizeQueryPlan(plan, now); err == nil {
			t.Fatalf("bucket structural bound %d ignored", bucket)
		}
	}
	plan.BucketSeconds = 60
	plan.GroupBy = append(append([]string{}, eight...), "protocol")
	if _, err := NormalizeQueryPlan(plan, now); err == nil {
		t.Fatal("nine group dimensions accepted")
	}
	plan.GroupBy = eight
	plan.Filter = &QueryFilterGroup{Groups: []QueryFilterGroup{{Conditions: []QueryPredicate{{Field: "in_if_name", Op: QueryRegex, Values: []string{"^inside"}}}}}}
	normalized, err := NormalizeQueryPlan(plan, now)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := QueryPlanPermissions(normalized); len(permissions) != 1 || permissions[0] != "metrics.read" {
		t.Fatalf("nested metadata predicate hid permission: %v", permissions)
	}
}

func TestQueryD102NestedEvaluationIsTypedAndFailClosed(t *testing.T) {
	group := &QueryFilterGroup{Match: "all", Groups: []QueryFilterGroup{
		{Match: "any", Conditions: []QueryPredicate{{Field: "dst_port", Op: QueryEqual, Values: []string{"443"}}, {Field: "src_as_name", Op: QueryContains, Values: []string{"Transit"}}}},
		{Match: "all", Mode: "exclude", Conditions: []QueryPredicate{{Field: "src_addr", Op: QueryCIDR, Values: []string{"192.0.2.0/24"}}}},
		{Conditions: []QueryPredicate{{Field: "raw_bytes", Op: QueryGreater, Values: []string{"9007199254740992"}}, {Field: "tcp_flag_names", Op: QueryBitAnd, Values: []string{"18"}}}},
	}}
	prepared, err := PrepareQueryFilter(group)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{"dst_port": "80", "src_as_name": "EXAMPLE TRANSIT", "src_addr": "198.51.100.1", "raw_bytes": "9007199254740993", "tcp_flag_names": "SYN,ACK"}
	if !prepared.Matches(func(name string) string { return fields[name] }) {
		t.Fatal("nested all/any/include/exclude result wrong")
	}
	fields["src_addr"] = "192.0.2.9"
	if prepared.Matches(func(name string) string { return fields[name] }) {
		t.Fatal("excluded nested CIDR leaked through")
	}
	fields["src_addr"] = "198.51.100.1"
	fields["raw_bytes"] = "9007199254740992"
	if prepared.Matches(func(name string) string { return fields[name] }) {
		t.Fatal("numeric comparison rounded past2^53")
	}
	if _, err := PrepareQueryFilter(&QueryFilterGroup{Saved: []QuerySavedFilterRef{{ID: "foreign-or-unresolved"}}}); err == nil {
		t.Fatal("unresolved saved reference evaluated as no filter")
	}
}

func TestQueryD103SliceCountsAreDistinctFromWindowCardinality(t *testing.T) {
	metrics, err := NormalizeQueryMetrics([]QueryMetric{{Measure: "unique_src", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "bucket_total", Role: "additional"}})
	if err != nil || len(metrics) != 2 {
		t.Fatalf("separate cardinality semantics unavailable: %+v %v", metrics, err)
	}
	if _, err := NormalizeQueryMetrics([]QueryMetric{{Measure: "bytes", Calculation: "bucket_total", Role: "primary"}}); err == nil {
		t.Fatal("distinct-observation calculation accepted on a byte counter")
	}
	for _, definition := range QueryMetricDefinitions() {
		for _, calculation := range definition.Calculations {
			if definition.CalculationUnits[calculation] == "" {
				t.Fatalf("missing unit for %s:%s", definition.Name, calculation)
			}
		}
	}
}
