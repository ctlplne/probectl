// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/pkg/sdk"
)

// Real current-user Postgres/RLS and HTTPS SDK/CLI/native transports; retained
// flow observations are modeled. Physical IPFIX and ClickHouse remain separate.
func TestServiceFlowDimensionsKeepTwoCurrentTenantReadersAcrossPublicTransports(t *testing.T) {
	f, original, _, at := newRoleFlowQueryFixture(t)
	rows := flowstore.NewMemory()
	for _, tenant := range f.tenants {
		var body bytes.Buffer
		if _, err := original.ExportTenant(t.Context(), tenant, &body); err != nil {
			t.Fatal(err)
		}
		decoder := json.NewDecoder(&body)
		for decoder.More() {
			var row flowstore.Row
			if err := decoder.Decode(&row); err != nil {
				t.Fatal(err)
			}
			// Row's private time axis is intentionally absent from JSON. These
			// modeled fixture observations were all inserted at the returned at.
			row.TS = at
			row.SrcService, row.SrcServiceRegion, row.SrcServiceProvider, row.SrcServiceStatus = "S3", "us-east-1", "aws", "known"
			row.DstService, row.DstServiceProvider, row.DstServiceStatus = "Cloudflare", "cloudflare", "known"
			if err := rows.Insert(t.Context(), []flowstore.Row{row}); err != nil {
				t.Fatal(err)
			}
		}
	}
	f.server.WithFlowStore(rows)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	native := newClientReportNativeProof(t, f, socket)
	plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"src_service", "src_service_region", "src_service_provider", "dst_service", "dst_service_region", "dst_service_status"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, View: "table"}
	query := ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &plan}
	input, err := json.Marshal(query)
	if err != nil {
		t.Fatal(err)
	}
	check := func(value explorerResult, want string) {
		t.Helper()
		if value.Flow == nil || len(value.Flow.Rows) != 1 || value.Flow.Totals["bytes:total"] != want {
			t.Fatal("public service query changed tenant totals", value.Flow, want)
		}
		group := value.Flow.Rows[0].Group
		if group["src_service"] != "S3" || group["src_service_region"] != "us-east-1" || group["src_service_provider"] != "aws" || group["dst_service"] != "Cloudflare" || group["dst_service_region"] != "" || group["dst_service_status"] != "known" {
			t.Fatal("service query lost labels or invented region", group)
		}
	}
	for lane, tenant := range f.tenants {
		want := fmt.Sprint(300 * (1 + 2*lane))
		client := sdk.NewClient(socket.URL, sdk.WithHTTPClient(socket.Client()), sdk.WithToken(f.tokens[tenant]))
		var body any = query
		response, err := client.QueryExplorer(t.Context(), sdk.QueryExplorerRequest{Body: &body})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(response)
		if err != nil {
			t.Fatal(err)
		}
		var value explorerResult
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		check(value, want)
		output, code := native.invokeCLI(tenant, nil, "explorer", "query", "--body", string(input))
		if code != 0 || json.Unmarshal(output, &value) != nil {
			t.Fatal("CLI refused service dimensions", code)
		}
		check(value, want)
		for _, wire := range []string{"2026-07-28", "2025-11-25"} {
			if wire == "2025-11-25" {
				proveLegacyMCPInitializationTLS(t, native.native, f.tokens[tenant])
			}
			caller := reportMCPClient{t: t, socket: native.native, protocolVersion: wire, foreignTenant: f.tenants[1-lane]}
			var result mcp.NativeFlowQueryResult
			caller.call(f.tokens[tenant], "flow_explorer_query", map[string]any{"plan": plan}, &result, true, "native service query refused")
			checkNativeServiceQuery(t, result, want)
			stream := openInterfaceRoleStdio(t, native.server, native.authenticator, f.tokens[tenant], wire, time.Minute)
			stream.call(t, wire, "flow_explorer_query", map[string]any{"plan": plan}, &result, true)
			checkNativeServiceQuery(t, result, want)
		}
	}
	primary, sibling := f.tenants[0], f.tenants[1]
	f.in(primary, func(ctx context.Context, scope tenancy.Scope) error {
		_, err := scope.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key='flow.read'`, primary, f.roles[primary])
		return err
	})
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		caller := reportMCPClient{t: t, socket: native.native, protocolVersion: wire}
		caller.call(f.tokens[primary], "flow_explorer_query", map[string]any{"plan": plan}, nil, false, "withdrawn current service reader was allowed")
		var result mcp.NativeFlowQueryResult
		caller.call(f.tokens[sibling], "flow_explorer_query", map[string]any{"plan": plan}, &result, true, "sibling service reader lost its own grant")
		checkNativeServiceQuery(t, result, "900")
	}
}

func checkNativeServiceQuery(t *testing.T, result mcp.NativeFlowQueryResult, want string) {
	t.Helper()
	if len(result.Flow.Rows) != 1 {
		t.Fatal("native service group omitted", result)
	}
	group := map[string]string{}
	for _, dimension := range result.Flow.Rows[0].Group {
		group[dimension.Field] = dimension.Value
	}
	if group["src_service"] != "S3" || group["src_service_region"] != "us-east-1" || group["dst_service"] != "Cloudflare" || group["dst_service_region"] != "" {
		t.Fatal("native service labels or unknown region changed", group)
	}
	for _, value := range result.Flow.Totals {
		if value.Metric == "bytes:total" && value.Value == want && value.Defined {
			return
		}
	}
	t.Fatal("native service totals were foreign, rounded or omitted", result.Flow.Totals, want)
}
