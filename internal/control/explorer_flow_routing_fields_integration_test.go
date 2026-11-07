// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Real TLS/application-role PG/current user and bearer authority. Historical
// flow rows are memory fixtures without routing captures: unknown metadata must
// retain their exact independent traffic. This is not a physical path proof.
func TestRoutingFieldsPreserveUnknownTrafficAcrossServedAndNativeReaders(t *testing.T) {
	f, rows, actors, at := newRoleFlowQueryFixture(t)
	f.server.WithFlowStore(rows.Memory)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "matrix", Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_bgp_origin_as", Op: flow.QueryEqual, Values: []string{""}}}, Groups: []flow.QueryFilterGroup{{Mode: "exclude", Conditions: []flow.QueryPredicate{{Field: "dst_bgp_next_hop_as", Op: flow.QueryBetween, Values: []string{"0", "4294967295"}}}}}}}
	for _, suffix := range []string{"bgp_provenance", "bgp_prefix", "bgp_as_paths", "bgp_next_hop_as", "bgp_origin_as", "bgp_first_transit_as", "bgp_rpki"} {
		plan.GroupBy = append(plan.GroupBy, "src_"+suffix)
		plan.MatrixWith = append(plan.MatrixWith, "dst_"+suffix)
	}
	read := func(tenant string) (int, explorerResult) {
		t.Helper()
		body, err := json.Marshal(ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &plan})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL+"/v1/explorer/query", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+f.tokens[tenant])
		req.Header.Set("Content-Type", "application/json")
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		var result explorerResult
		if response.StatusCode == http.StatusOK {
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
		}
		return response.StatusCode, result
	}
	for lane, tenant := range f.tenants {
		want := []string{"300", "900"}[lane]
		code, result := read(tenant)
		if code != http.StatusOK || result.Flow == nil || result.Flow.Totals["bytes:total"] != want || len(result.Flow.Matrix) != 1 {
			t.Fatal("registered routing fields lost unknown traffic or tenant totals", code, result.Flow)
		}
		for _, axis := range []map[string]string{result.Flow.Matrix[0].Row, result.Flow.Matrix[0].Column} {
			if len(axis) != 7 {
				t.Fatal("routing query lost a registered direction field", axis)
			}
			for name, value := range axis {
				expected := ""
				if strings.HasSuffix(name, "_provenance") {
					expected = "unavailable"
				} else if strings.HasSuffix(name, "_rpki") {
					expected = "unknown"
				}
				if value != expected {
					t.Fatal("missing routing receipt invented a path, ASN or provenance", name, value)
				}
			}
		}
		ctx := auth.WithPrincipal(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), actors[tenant])
		raw, failed := nativeControlCall(t, nativeControlMCP(t, f.server), actors[tenant], "flow_explorer_query", map[string]any{"plan": plan})
		var native mcp.NativeFlowQueryResult
		if failed || json.Unmarshal(raw, &native) != nil || len(native.Flow.Totals) != 1 || native.Flow.Totals[0].Value != want || len(native.Flow.Matrix) != 1 {
			t.Fatal("native routing query lost complete unknown traffic or tenant authority", failed, string(raw))
		}
		limited := narrowPrincipalToScopes(auth.ClonePrincipal(actors[tenant]), []string{permAIQuery, permFlowRead, "entities.read"})
		if _, err := (nativeMCPFlowBackend{f.server}).FlowQuery(auth.WithPrincipal(ctx, limited), limited, plan); err == nil {
			t.Fatal("registered routing query widened a credential without BGP access")
		}
	}
	red, blue := f.tenants[0], f.tenants[1]
	f.in(red, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='events.read'`, red, f.roles[red])
		return err
	})
	if code, _ := read(red); code != http.StatusForbidden {
		t.Fatal("registered routing fields bypassed current source revocation", code)
	}
	if code, result := read(blue); code != http.StatusOK || result.Flow == nil || result.Flow.Totals["bytes:total"] != "900" {
		t.Fatal("routing source revocation crossed the tenant storage boundary", code)
	}
}
