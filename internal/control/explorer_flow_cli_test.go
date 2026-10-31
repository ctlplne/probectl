// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/store/flowstore"
)

func TestExplorerCLIExpandedPlanAndFiltersOverPairedTLSAPI(t *testing.T) {
	const red = "00000000-0000-0000-0000-000000000001"
	const blue = "00000000-0000-0000-0000-000000000002"
	at := time.Date(2026, 10, 28, 1, 0, 0, 0, time.UTC)
	records := flowstore.NewMemory()
	rows := []flowstore.Row{}
	for i, tenant := range []string{red, blue} {
		for _, offset := range []time.Duration{0, -400 * 24 * time.Hour} {
			rows = append(rows, flowstore.Row{TenantID: tenant, TS: at.Add(offset), Exporter: "router", SrcAddr: fmt.Sprintf("192.0.2.%d", i+1), DstAddr: "203.0.113.1", SrcPort: 1000, DstPort: 443, Transport: "tcp", Protocol: "netflow5", BytesScaled: 9007199254740993 + uint64(i), PacketsScaled: 5})
		}
	}
	if err := records.Insert(t.Context(), rows); err != nil {
		t.Fatal(err)
	}
	filters := flow.NewMemoryQueryFilterStore(0)
	srv := testServer(fakePinger{}).WithFlowStore(records).WithFlowQueryFilters(filters)
	server := httptest.NewTLSServer(srv.Handler())
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "qa-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	invoke := func(tenant string, input []byte, args ...string) (string, string, int) {
		t.Helper()
		var out, errs bytes.Buffer
		env := func(k string) string {
			switch k {
			case "PROBECTL_API_URL":
				return server.URL
			case "PROBECTL_CA_FILE":
				return ca
			case "PROBECTL_TENANT":
				return tenant
			}
			return ""
		}
		status := cli.RunWithStdin(append([]string{"--json", "explorer"}, args...), env, bytes.NewReader(input), &out, &errs)
		return out.String(), errs.String(), status
	}
	dims := []string{"exporter", "src_addr", "dst_addr", "src_port", "dst_port", "transport", "protocol", "in_if"}
	plan := flow.QueryPlan{From: at.Add(-401 * 24 * time.Hour), To: at.Add(time.Hour), GroupBy: dims, View: "matrix", MatrixWith: dims, BucketSeconds: 604800, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "packets", Calculation: "p99", Role: "secondary"}, {Measure: "unique_src", Calculation: "max", Role: "secondary"}, {Measure: "unique_dst", Calculation: "bucket_total", Role: "secondary"}}}
	query := ai.ExplorerQuery{Question: "Eight dimensional traffic over tenant retention", Source: ai.ExplorerFlow, Flow: &plan}
	body, err := json.Marshal(query)
	if err != nil {
		t.Fatal(err)
	}
	// More than1MiB must work through the CLI without changing its2MiB grammar.
	padded := append(bytes.Repeat([]byte{' '}, (1<<20)+1), body...)
	for i, tenant := range []string{red, blue} {
		own := fmt.Sprintf("192.0.2.%d", i+1)
		foreign := fmt.Sprintf("192.0.2.%d", 2-i)
		out, errs, status := invoke(tenant, padded, "query", "--body-file", "-")
		if status != 0 || !strings.Contains(out, own) || strings.Contains(out, foreign) || !strings.Contains(out, "1801439850948198") || !strings.Contains(out, `"matrix"`) {
			t.Fatalf("query lane%d code%d err%s out%s", i, status, errs, out)
		}
		create := saveFlowFilterRequest{Name: "filter-" + own, Expression: flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_addr", Op: flow.QueryEqual, Values: []string{own}}}}}
		input, err := json.Marshal(create)
		if err != nil {
			t.Fatal(err)
		}
		out, errs, status = invoke(tenant, input, "filter-create", "--body-file", "-")
		if status != 0 {
			t.Fatalf("filter create=%d %s %s", status, errs, out)
		}
		var item flow.SavedQueryFilter
		if err := json.Unmarshal([]byte(out), &item); err != nil {
			t.Fatal(err)
		}
		other := red
		if tenant == red {
			other = blue
		}
		if out, errs, status = invoke(other, nil, "filter-get", item.ID); status == 0 || strings.Contains(out, own) || !strings.Contains(errs, "not found") {
			t.Fatalf("foreign CLI lookup=%d %s %s", status, errs, out)
		}
		if out, errs, status = invoke(tenant, nil, "filter-list", "--query", "limit=1"); status != 0 || !strings.Contains(out, item.ID) || strings.Contains(out, foreign) {
			t.Fatalf("list=%d %s %s", status, errs, out)
		}
		// An observed version must survive CLI update and delete requests.
		forVersionTest := flow.SaveQueryFilter{ID: item.ID, Version: 1, Name: "updated", Expression: item.Expression}
		saved, err := filters.SaveQueryFilter(t.Context(), tenant, "op", forVersionTest)
		if err != nil {
			t.Fatal(err)
		}
		update := saveFlowFilterRequest{Name: "CLI updated", Version: saved.Version, Expression: item.Expression}
		input, err = json.Marshal(update)
		if err != nil {
			t.Fatal(err)
		}
		if out, errs, status = invoke(tenant, input, "filter-update", item.ID, "--body-file", "-"); status != 0 || !strings.Contains(out, `"version": 3`) {
			t.Fatalf("update=%d %s %s", status, errs, out)
		}
		if out, errs, status = invoke(tenant, nil, "filter-delete", item.ID, "--query", "version=3"); status != 0 {
			t.Fatalf("delete=%d %s %s", status, errs, out)
		}
	}
}
