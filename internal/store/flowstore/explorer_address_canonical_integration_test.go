// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tags"
)

func TestExplorerClickHouseCanonicalAddressesRetainValidIPv6(t *testing.T) {
	store := explorerIntegrationStore(t)
	t.Cleanup(func() { _ = store.Close() })
	a, b, definitionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	t.Cleanup(func() { cleanupExplorerFixtureTenant(t, store, a); cleanupExplorerFixtureTenant(t, store, b) })
	addresses := []string{"::ffff:1:1:1", "::ffff:1", "::a:b", "192.0.2.10", "::ffff:192.0.2.10", "::ffff:c000:20a", "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1", "::", "::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}
	at := explorerFixtureRow(a).TS
	want := map[string]uint64{}
	var rows []Row
	for i, address := range addresses {
		canonical := netip.MustParseAddr(address).Unmap().String()
		want[canonical] += uint64((i + 1) * 100)
		for lane, tenant := range []string{a, b} {
			row := explorerFixtureRow(tenant)
			row.TS, row.StartTS = at, at.Add(-time.Second)
			row.AgentID, row.Exporter, row.SrcAddr, row.DstAddr = "untrusted-sender", address, address, address
			row.SrcPort = uint16(1000 + i)
			row.BytesScaled = uint64((i + 1) * 100 * (1 + lane*8))
			rows = append(rows, row)
		}
	}
	if err := store.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	for lane, tenant := range []string{a, b} {
		var roots []tags.ExporterProjection
		var total uint64
		for address, count := range want {
			roots = append(roots, tags.ExporterProjection{Exporter: address, Values: map[string]string{"customer": tenant + "|" + address}})
			total += count * uint64(1+lane*8)
		}
		lookup, err := NewTagQueryData(tenant, 1, []tags.Definition{{TenantID: tenant, ID: definitionID, Key: "customer"}}, roots, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Hour), GroupBy: []string{"exporter", "src_addr", "dst_addr", "tag.customer"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
		for _, source := range []string{"raw", "rollup"} {
			plan.DataSeries, plan.Filter = source, nil
			result, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Plan: plan, Tags: lookup})
			if err != nil {
				t.Fatalf("address fixture query could not execute: %v", err)
			}
			if len(result.Rows) != len(want) || result.Totals["bytes:total"] != strconv.FormatUint(total, 10) {
				t.Fatalf("canonical address query lost valid owned input: %s %v", source, err)
			}
			for _, row := range result.Rows {
				address := row.Group["exporter"]
				count, ok := want[address]
				if !ok || row.Group["src_addr"] != address || row.Group["dst_addr"] != address || row.Group["tag.customer"] != tenant+"|"+address || row.Metrics["bytes:total"] != strconv.FormatUint(count*uint64(1+lane*8), 10) {
					t.Fatalf("canonical address query lost valid owned input: %s address=%q", source, address)
				}
			}
			for address, count := range want {
				plan.Filter = &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_addr", Op: flow.QueryEqual, Values: []string{address}}}}
				filtered, err := store.ExplorePlan(t.Context(), PlanQuery{TenantID: tenant, Plan: plan, Tags: lookup})
				if err != nil {
					t.Fatalf("address fixture filter could not execute: %v", err)
				}
				if len(filtered.Rows) != 1 || filtered.Totals["bytes:total"] != strconv.FormatUint(count*uint64(1+lane*8), 10) {
					t.Fatalf("canonical address query lost valid owned input: %s exact filter=%q: %v", source, address, err)
				}
			}
		}
	}
}
