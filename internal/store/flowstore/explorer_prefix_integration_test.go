// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestExplorerClickHousePrefixTagsKeepOwnedContextAndExactRanges(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	memory := NewMemory()
	a, b, contextID, otherContext, definitionID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	t.Cleanup(func() { cleanupExplorerFixtureTenant(t, store, a); cleanupExplorerFixtureTenant(t, store, b) })
	type input struct{ exporter, source, destination, sourceTag, destinationTag string }
	inputs := []input{
		{"192.0.2.90", "198.51.100.1", "2001:db8:1::1", "child", "host6"},
		{"192.0.2.90", "198.51.100.2", "2001:db8:1::2", "", ""},
		{"192.0.2.90", "198.51.100.80", "2001:db8:2::1", "v4", "v6"},
		{"192.0.2.90", "198.51.100.200", "203.0.113.10", "host", "v4default"},
		{"192.0.2.90", "198.51.100.201", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "", "v6last"},
		{"192.0.2.90", "0.0.0.0", "::", "v4zero", "v6zero"},
		{"::ffff:192.0.2.90", "255.255.255.255", "::ffff:198.51.100.80", "v4last", "v4"},
		{"192.0.2.90", "::ffff:1:1:1", "::ffff:1", "v6default", "v6default"},
		{"192.0.2.90", "bad-address", "2001:db8:2::2", "", "v6"},
		{"192.0.2.91", "203.0.113.2", "203.0.114.1", "other-context", ""},
		{"192.0.2.91", "203.0.112.1", "0.0.0.0", "", ""},
		{"192.0.2.99", "198.51.100.80", "2001:db8:2::1", "", ""},
		{"192.0.2.90%en0", "198.51.100.80", "2001:db8:2::1", "", ""},
		{"192.0.2.90", "fe80::1%en0", "", "", ""},
	}
	at := explorerFixtureRow(a).TS
	var rows []Row
	for lane, tenant := range []string{a, b} {
		for i, item := range inputs {
			row := explorerFixtureRow(tenant)
			row.TS, row.StartTS = at, at.Add(-time.Second)
			row.AgentID = "untrusted-sender"
			row.Exporter, row.SrcAddr, row.DstAddr = item.exporter, item.source, item.destination
			row.SrcPort = uint16(1000 + i)
			row.BytesScaled = uint64((i + 1) * 100 * (1 + lane*8))
			rows = append(rows, row)
		}
	}
	for _, backend := range []Store{store, memory} {
		if err := backend.Insert(t.Context(), rows); err != nil {
			t.Fatal(err)
		}
	}
	prefixIDs := map[int]string{}
	for lane, tenant := range []string{a, b} {
		value := func(label string) string {
			if label == "" {
				return ""
			}
			return tenant + "|" + label
		}
		var prefixes []tags.PrefixProjection
		add := func(context, network, label string) {
			index := len(prefixes)
			if prefixIDs[index] == "" {
				prefixIDs[index] = uuid.NewString()
			}
			id := prefixIDs[index]
			values := map[string]string{}
			if label != "" {
				values["customer"] = value(label)
			}
			prefixes = append(prefixes, tags.PrefixProjection{Scope: tags.Scope{TenantID: tenant, ContextID: context}, ID: id, Network: netip.MustParsePrefix(network), Values: values})
		}
		for _, item := range [][2]string{
			{"0.0.0.0/0", "v4default"}, {"198.51.100.0/24", "v4"},
			{"198.51.100.128/25", ""}, {"198.51.100.200/32", "host"},
			{"198.51.100.0/26", "ambiguous"}, {"198.51.100.0/26", "ambiguous"},
			{"198.51.100.1/32", "child"}, {"0.0.0.0/32", "v4zero"},
			{"255.255.255.255/32", "v4last"}, {"::/0", "v6default"},
			{"2001:db8::/32", "v6"}, {"2001:db8:1::/48", ""},
			{"2001:db8:1::1/128", "host6"}, {"::/128", "v6zero"},
			{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "v6last"},
		} {
			// Tenant-local identifiers may coincide across tenants; only the
			// authenticated tenant and owned context select their values.
			add(contextID, item[0], item[1])
		}
		add(otherContext, "203.0.113.0/24", "other-context")
		lookup, err := NewTagQueryData(tenant, 1,
			[]tags.Definition{{TenantID: tenant, ID: definitionID, Key: "customer"}},
			[]tags.ExporterProjection{{Exporter: "192.0.2.90", ContextID: contextID, Values: map[string]string{"customer": value("exporter")}}, {Exporter: "192.0.2.91", ContextID: otherContext, Values: map[string]string{"customer": value("exporter")}}},
			1<<20, TagQuerySources{Context: t.Context(), Prefixes: prefixes})
		if err != nil {
			t.Fatal(err)
		}
		base := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Hour), View: "table",
			GroupBy: []string{"src_port", "src_addr", "dst_addr", "tag.customer", "tag.src_prefix.customer", "tag.dst_prefix.customer"},
			Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "bytes", Calculation: "p95", Role: "secondary"}, {Measure: "bytes", Calculation: "p99", Role: "secondary"}}}
		compare := func(plan flow.QueryPlan) PlanResult {
			t.Helper()
			referencePlan := plan
			referencePlan.DataSeries = "raw"
			want, err := memory.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Plan: referencePlan, Tags: lookup})
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("prefix query checkpoint source=%s view=%s groupings=%d matrix=%d metrics=%d", plan.DataSeries, plan.View, len(plan.GroupBy), len(plan.MatrixWith), len(plan.Metrics))
			got, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Plan: plan, Tags: lookup})
			if err != nil {
				t.Fatalf("owned prefix range query failed: %v", err)
			}
			if got.Source != plan.DataSeries || got.Coverage == nil || !got.Coverage.CompleteInputs || got.TagTenantID != tenant || got.TagIDs["tag.src_prefix.customer"] != definitionID || got.TagIDs["tag.dst_prefix.customer"] != definitionID {
				t.Fatal("owned prefix query lost complete source or immutable field identity")
			}
			for _, field := range []string{"exporter", "src_addr", "dst_addr", "tag.src_prefix.customer", "tag.dst_prefix.customer"} {
				if !slices.Contains(got.Coverage.Fields, field) {
					t.Fatal("prefix source omitted required input", field)
				}
			}
			want.Query.DataSeries = got.Query.DataSeries
			if got.Source == "rollup" {
				if got.ResolutionSeconds != 60 {
					t.Fatal("complete retained prefix input lost hourly resolution")
				}
				want.Source, want.Coverage, want.ResolutionSeconds = got.Source, got.Coverage, got.ResolutionSeconds
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatal("owned prefix SQL/reference results differ")
			}
			return got
		}
		for _, source := range []string{"raw", "rollup"} {
			base.DataSeries = source
			result := compare(base)
			if len(result.Rows) != len(inputs) {
				t.Fatal("prefix join changed row multiplicity")
			}
			seen := map[int]bool{}
			var total uint64
			for _, row := range result.Rows {
				port, err := strconv.Atoi(row.Group["src_port"])
				i := port - 1000
				if err != nil || i < 0 || i >= len(inputs) || seen[i] {
					t.Fatal("prefix join returned duplicate or foreign row")
				}
				seen[i] = true
				item := inputs[i]
				count := uint64((i + 1) * 100 * (1 + lane*8))
				total += count
				root := value("exporter")
				if item.exporter == "192.0.2.99" || item.exporter == "192.0.2.90%en0" {
					root = ""
				}
				if row.Group["tag.customer"] != root || row.Group["tag.src_prefix.customer"] != value(item.sourceTag) || row.Group["tag.dst_prefix.customer"] != value(item.destinationTag) || row.Metrics["bytes:total"] != strconv.FormatUint(count, 10) {
					t.Fatalf("prefix ownership/range/specificity changed for fixture row %d", i)
				}
			}
			if result.Totals["bytes:total"] != strconv.FormatUint(total, 10) {
				t.Fatal("prefix join changed exact tenant total")
			}
			matrix := base
			matrix.View = "matrix"
			matrix.GroupBy = append(append([]string{}, base.GroupBy...), "exporter", "in_if")
			matrix.MatrixWith = []string{"tag.dst_prefix.customer", "tag.src_prefix.customer", "dst_addr", "src_addr", "src_port", "dst_port", "protocol", "transport"}
			matrix.RowLimit, matrix.MatrixDepth = 2, 1
			compare(matrix)
			filtered := base
			filtered.Filter = &flow.QueryFilterGroup{Match: "all", Groups: []flow.QueryFilterGroup{
				{Match: "any", Conditions: []flow.QueryPredicate{{Field: "tag.src_prefix.customer", Op: flow.QueryEqual, Values: []string{value("child")}}, {Field: "tag.dst_prefix.customer", Op: flow.QueryRegex, Values: []string{"v6$"}}}},
				{Mode: "exclude", Conditions: []flow.QueryPredicate{{Field: "tag.src_prefix.customer", Op: flow.QueryEqual, Values: []string{""}}}},
			}}
			if result := compare(filtered); len(result.Rows) == 0 {
				t.Fatal("nested prefix filter lost every matching input")
			}
		}
	}
}
