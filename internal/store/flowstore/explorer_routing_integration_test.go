// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"bytes"
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/chclient"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Uses the real TLS tenant-setting reader and retained raw/hourly rows. Only
// the routing metadata is modeled; no current actor or physical source grant
// is claimed by this storage-join proof.
func proveRoutingQueryJoinsInRealStore(t *testing.T, store *ClickHouse, tenants []string, rows []Row, count int) {
	t.Helper()
	var first []explorerExternalData
	for lane, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		ctx = withExplorerBudget(ctx, DefaultExplorerBudget())
		origin := strconv.FormatUint(uint64(^uint32(0))-uint64(lane), 10)
		encoded, err := json.Marshal([]string{strings.Repeat("64500 ", 65_537) + origin})
		if err != nil {
			t.Fatal(err)
		}
		fields := map[string]string{"src_bgp_as_paths": string(encoded), "src_bgp_origin_as": origin, "src_bgp_provenance": "router_selected"}
		projections := make([]RoutingProjection, 0, count-1)
		for i, row := range rows[lane*count : (lane+1)*count] {
			if i == 0 { // Missing metadata must retain the traffic as unknown.
				continue
			}
			read, err := routingReadFromRow(row)
			if err != nil {
				t.Fatal(err)
			}
			if i == 1 {
				read.Ref.CapturedAt = read.Ref.CapturedAt.Add(time.Nanosecond)
			}
			if i == 2 {
				read.Ref.Key[0] ^= 1
			}
			projections = append(projections, RoutingProjection{Scope: entity.Scope{TenantID: tenant, ContextID: "33333333-3333-4333-8333-333333333333"}, Key: read.Ref.Key, Clock: read.Ref.CapturedAt.UnixNano(), Fields: fields, SourceIDs: []string{"modeled/current-routing-source"}, FactsID: [32]byte{31: 1}})
		}
		data, err := newRoutingQueryData(ctx, tenant, time.Now(), projections, DefaultExplorerBudget().MemoryBytes/4)
		if err != nil {
			t.Fatal(err)
		}
		external, err := data.externalData(ctx, tenant, DefaultExplorerBudget().MemoryBytes/4)
		if err != nil {
			t.Fatal(err)
		}
		if lane == 0 {
			first = external
		}
		var grafted []explorerExternalData
		if lane == 1 {
			grafted = graftForeignRoutingFactsForTest(t, first, tenant, rows[lane*count+1:(lane+1)*count])
		}
		reader, err := store.readLane(Target{}, tenant)
		if err != nil || !reader.Reader {
			t.Fatal("routing join proof lacks its independent tenant-setting reader", err)
		}
		for _, table := range []string{sharedFlowsTable, sharedFlowRollupsTable} {
			params := chParams{"tenant": tenant}
			pathField, _ := flow.RoutingQueryField("src_bgp_as_paths")
			originField, _ := flow.RoutingQueryField("src_bgp_origin_as")
			provenanceField, _ := flow.RoutingQueryField("src_bgp_provenance")
			from := planRoutingJoinsSQL(table+" FINAL", flow.QueryPlan{GroupBy: []string{pathField.Name}})
			sql := "SELECT " + routingQueryFieldSQL(pathField, params) + " AS captured_paths," + routingQueryFieldSQL(originField, params) + " AS captured_origin," + routingQueryFieldSQL(provenanceField, params) + " AS captured_provenance,count() AS population FROM " + from + " WHERE tenant_id={tenant:String} GROUP BY captured_paths,captured_origin,captured_provenance"
			settings, err := DefaultExplorerBudget().settings()
			if err != nil {
				t.Fatal(err)
			}
			sql += "\n" + settings
			got, err := store.explorerQueryRows(ctx, Target{}, reader, tenant, sql, params, external...)
			if err != nil || len(got) != 2 {
				t.Fatal("actual routing join lost known or unknown retained traffic", table, len(got), err)
			}
			known, unknown := false, false
			for _, group := range got {
				if chToString(group["captured_provenance"]) == "router_selected" {
					// UInt32 is an unquoted JSON number; chclient.Decode keeps
					// its exact decimal text with UseNumber. String-only
					// coercion loses every valid ASN before the assertion.
					capturedOrigin, numeric := group["captured_origin"].(json.Number)
					known = chToString(group["captured_paths"]) == string(encoded) && numeric && capturedOrigin.String() == origin && chToString(group["population"]) == strconv.Itoa(count-3)
				} else {
					unknown = chToString(group["captured_provenance"]) == "unavailable" && chToString(group["captured_paths"]) == "" && group["captured_origin"] == nil && chToString(group["population"]) == "3"
				}
			}
			if !known || !unknown {
				t.Fatal("actual routing join changed complete paths, full ASN, key/clock or missing-row semantics", table, known, unknown)
			}
			proveRoutingPredicateCountsInRealStore(t, ctx, store, reader, tenant, from, external, count, origin)
			if lane == 1 {
				for _, attack := range [][]explorerExternalData{first, grafted} {
					foreign, err := store.explorerQueryRows(ctx, Target{}, reader, tenant, sql, params, attack...)
					if err != nil || len(foreign) != 1 || chToString(foreign[0]["captured_provenance"]) != "unavailable" || chToString(foreign[0]["captured_paths"]) != "" || foreign[0]["captured_origin"] != nil || chToString(foreign[0]["population"]) != strconv.Itoa(count) {
						t.Fatal("routing join reused another tenant's path metadata or lost its traffic", table, err)
					}
				}
			}
		}
	}
}

func proveRoutingPredicateCountsInRealStore(t *testing.T, ctx context.Context, store *ClickHouse, reader chclient.ReadLane, tenant, from string, external []explorerExternalData, count int, origin string) {
	t.Helper()
	for _, test := range []struct {
		op      flow.QueryOperator
		values  []string
		exclude bool
		want    int
	}{
		{flow.QueryEqual, []string{""}, false, 3},
		{flow.QueryEqual, []string{"0"}, false, 0},
		{flow.QueryEqual, []string{origin}, false, count - 3},
		{flow.QueryNotEqual, []string{""}, false, count - 3},
		{flow.QueryNotEqual, []string{"0"}, false, count},
		{flow.QueryIn, []string{"", origin}, false, count},
		{flow.QueryNotIn, []string{"", origin}, false, 0},
		{flow.QueryBetween, []string{"0", "4294967295"}, false, count - 3},
		{flow.QueryNotBetween, []string{"0", "4294967295"}, false, 0},
		{flow.QueryBetween, []string{"0", "4294967295"}, true, 3},
	} {
		group := &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_bgp_origin_as", Op: test.op, Values: test.values}}}
		if test.exclude {
			group = &flow.QueryFilterGroup{Groups: []flow.QueryFilterGroup{{Mode: "exclude", Groups: []flow.QueryFilterGroup{*group}}}}
		}
		params := chParams{"tenant": tenant}
		predicate, err := explorerFilterSQL(group, params)
		if err != nil {
			t.Fatal(err)
		}
		settings, err := DefaultExplorerBudget().settings()
		if err != nil {
			t.Fatal(err)
		}
		query := "SELECT count() AS population FROM " + from + " WHERE tenant_id={tenant:String} AND " + predicate + "\n" + settings
		got, err := store.explorerQueryRows(ctx, Target{}, reader, tenant, query, params, external...)
		if err != nil || len(got) != 1 || chToString(got[0]["population"]) != strconv.Itoa(test.want) {
			t.Fatal("actual routing predicate confused unknown, zero, full ASN or nested exclusion", test.op, test.exclude, err, got)
		}
	}
}

// Model a broken request-local cache grafting foreign fact bodies onto valid
// references for this tenant. The second join must independently bind facts to
// the tenant even after every key/clock/reference selector has been replaced.
func graftForeignRoutingFactsForTest(t *testing.T, foreign []explorerExternalData, tenant string, rows []Row) []explorerExternalData {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(foreign[0].rows))
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	for _, row := range rows {
		var ref map[string]string
		if err := decoder.Decode(&ref); err != nil {
			t.Fatal(err)
		}
		ref["routing_ref_tenant"], ref["routing_key"], ref["routing_clock"] = tenant, row.RoutingCaptureKey, strconv.FormatInt(row.RoutingCapturedUnixNanos, 10)
		if err := encoder.Encode(ref); err != nil {
			t.Fatal(err)
		}
	}
	if decoder.More() {
		t.Fatal("foreign routing graft did not consume its complete reference table")
	}
	return []explorerExternalData{{kind: externalRoutingReferences, rows: body.Bytes()}, foreign[1]}
}
