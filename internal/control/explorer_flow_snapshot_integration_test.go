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
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/cli"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

type snapshotAPISource struct {
	*flowstore.Memory
	queries atomic.Int64
}

func (s *snapshotAPISource) ExplorePlan(ctx context.Context, query flowstore.PlanQuery) (flowstore.PlanResult, error) {
	s.queries.Add(1)
	return s.Memory.ExplorePlan(ctx, query)
}

func TestExplorerSnapshotPostgresRealPairedTLSReplicasAndCLI(t *testing.T) {
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "snapshot API PostgreSQL configuration unavailable")
		return
	}
	t.Cleanup(admin.Close)
	if err := admin.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "snapshot API PostgreSQL unavailable")
		return
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, admin); err != nil {
		t.Fatal(err)
	}
	pool := admin
	if dsn := os.Getenv("PROBECTL_FLOW_FILTER_TEST_DATABASE_URL"); dsn != "" {
		pool, err = pgxpool.New(ctx, dsn)
		if err != nil {
			t.Fatal("runtime database configuration invalid")
		}
		t.Cleanup(pool.Close)
	}
	objects, err := objectstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("qa-snapshot-api-only", base64.StdEncoding.EncodeToString(key))
	crypto.Zeroize(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	tenants := store.NewTenants(pool)
	red, err := tenants.Create(ctx, fmt.Sprintf("fx1-snapshot-api-red-%d", time.Now().UnixNano()), "Red")
	if err != nil {
		t.Fatal(err)
	}
	blue, err := tenants.Create(ctx, fmt.Sprintf("fx1-snapshot-api-blue-%d", time.Now().UnixNano()), "Blue")
	if err != nil {
		t.Fatal(err)
	}
	source := &snapshotAPISource{Memory: flowstore.NewMemory()}
	engine := tenantlife.New(pool, source, objects, nil, nil, "QA fixture has no backups", nil)
	t.Cleanup(func() {
		for _, tenant := range []*store.Tenant{red, blue} {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			attestation, err := engine.Erase(cleanup, tenant.ID, tenant.Slug, "qa-fixture")
			cancel()
			if err != nil || !attestation.Complete {
				t.Errorf("own API fixture cleanup: %+v %v", attestation, err)
			}
		}
	})
	// The test binary's explicit dev-auth fixture supplies principals; this is
	// a real TLS/API/CLI + PG/FS proof, not a release-binary SSO/sender proof.
	previousHook := devModeHook
	devModeHook = func(s *Server, w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
		p, handled := previousHook(s, w, r)
		if p != nil && r.Header.Get("X-QA-Other-Owner") == "true" {
			p.UserID = "other-qa-user"
		}
		return p, handled
	}
	t.Cleanup(func() { devModeHook = previousHook })
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	input := make([]flowstore.Row, 50001)
	for i := 0; i < 50000; i++ {
		input[i] = flowstore.Row{TenantID: red.ID, AgentID: "qa-collector", Exporter: "192.0.2.1", TS: at, SrcAddr: "198.51.100.1", DstAddr: "203.0.113.1", SrcPort: uint16(i + 1), DstPort: 443, BytesScaled: 9007199254740993 + uint64(i), PacketsScaled: 1}
	}
	input[50000] = flowstore.Row{TenantID: blue.ID, AgentID: "qa-sibling", Exporter: "192.0.2.2", TS: at, SrcAddr: "198.51.100.2", DstAddr: "203.0.113.2", SrcPort: 65500, DstPort: 443, BytesScaled: 987654321, PacketsScaled: 1}
	if err := source.Insert(ctx, input); err != nil {
		t.Fatal(err)
	}
	makeReplica := func() *httptest.Server {
		srv := testServer(fakePinger{}).WithFlowStore(source).WithTenantLife(engine).WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(pool, 0, audit.TenantRecord)).WithFlowQueryViews(flow.NewPostgresQueryViewStore(pool, 0, audit.TenantRecord)).WithFlowSnapshotStorage(FlowSnapshotStorage{Pool: pool, Objects: objects, Router: tenancy.PooledRouter{}, Fence: tenancy.NewPostgresWriterFence(pool), DeploymentRetentionDays: 0, Cache: flowsnapshot.Config{TempDir: t.TempDir()}})
		server := httptest.NewTLSServer(srv.Handler())
		t.Cleanup(server.Close)
		return server
	}
	first, second := makeReplica(), makeReplica()
	request := func(server *httptest.Server, tenant string, body any, headers map[string]string) (int, []byte) {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/v1/explorer/query", bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Probectl-Tenant", tenant)
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode, data
	}
	query := ai.ExplorerQuery{Question: "Fifty thousand frozen groups", Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{From: at.Add(-time.Hour), To: at.Add(time.Hour), GroupBy: []string{"src_port"}, View: "table", BucketSeconds: 3600, RowLimit: 50000, PageSize: 4999, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}}
	status, body := request(first, red.ID, query, nil)
	if status != http.StatusOK {
		t.Fatalf("create %d: %.600s", status, body)
	}
	var page explorerResult
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if page.FlowPaging == nil || !page.FlowPaging.More || page.FlowPaging.SelectedRows != 50000 || page.Flow == nil {
		t.Fatal("missing native paging metadata")
	}
	initial := page
	totals := page.Flow.Totals["bytes:total"]
	late := input[0]
	late.SrcPort = 60000
	late.BytesScaled = ^uint64(0)
	if err := source.Insert(ctx, []flowstore.Row{late}); err != nil {
		t.Fatal(err)
	}
	count := 0
	for {
		if page.FlowPaging.Offset != count || page.Flow.Totals["bytes:total"] != totals || page.Truncated || page.Execution.Truncated {
			t.Fatalf("paging changed global meaning: offset%d expected%d selected%d truncated%t/%t", page.FlowPaging.Offset, count, page.FlowPaging.SelectedRows, page.Truncated, page.Execution.Truncated)
		}
		for _, row := range page.Flow.Rows {
			port := 50000 - count
			expected := strconv.FormatUint(9007199254740993+uint64(port-1), 10)
			if row.Group["src_port"] != strconv.Itoa(port) || row.Metrics["bytes:total"] != expected {
				t.Fatalf("changed/rounded/duplicate row at offset%d", count)
			}
			count++
		}
		if page.FlowPaging.NextCursor == "" {
			break
		}
		continuation := map[string]any{"source": "flow", "flow": map[string]string{"cursor": page.FlowPaging.NextCursor}}
		status, body = request(second, red.ID, continuation, nil)
		if status != http.StatusOK {
			t.Fatalf("resume %d: %.600s", status, body)
		}
		// Decode into a fresh response: omitted optional fields (notably the
		// final next_cursor) must not retain the preceding response's value.
		page = explorerResult{}
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
	}
	if count != 50000 || source.queries.Load() != 1 {
		t.Fatalf("paging %d rows / %d source executions", count, source.queries.Load())
	}
	continuation := map[string]any{"source": "flow", "flow": map[string]string{"cursor": initial.FlowPaging.NextCursor}}
	for _, test := range []struct {
		name, tenant string
		headers      map[string]string
		expected     int
	}{{"foreign tenant", blue.ID, nil, http.StatusNotFound}, {"foreign owner", red.ID, map[string]string{"X-QA-Other-Owner": "true"}, http.StatusNotFound}, {"revoked source", red.ID, map[string]string{testWithholdPermissionsHeader: permFlowRead}, http.StatusForbidden}} {
		status, body := request(second, test.tenant, continuation, test.headers)
		if status != test.expected {
			t.Fatalf("%s %d: %.600s", test.name, status, body)
		}
	}
	overridden := map[string]any{"source": "flow", "question": "a different meaning", "flow": map[string]string{"cursor": initial.FlowPaging.NextCursor}}
	if status, _ := request(second, red.ID, overridden, nil); status != http.StatusUnprocessableEntity {
		t.Fatalf("cursor override accepted: %d", status)
	}
	ca := filepath.Join(t.TempDir(), "qa-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(continuation)
	var out, errs bytes.Buffer
	code := cli.RunWithStdin([]string{"--json", "explorer", "query", "--body-file", "-"}, func(key string) string {
		switch key {
		case "PROBECTL_API_URL":
			return second.URL
		case "PROBECTL_CA_FILE":
			return ca
		case "PROBECTL_TENANT":
			return red.ID
		}
		return ""
	}, bytes.NewReader(encoded), &out, &errs)
	if code != 0 || !strings.Contains(out.String(), `"offset": 4999`) {
		t.Fatalf("CLI continuation failed code%d err%.500s out%.500s", code, errs.String(), out.String())
	}
	if source.queries.Load() != 1 {
		t.Fatal("CLI continuation reran source query")
	}
	download := func(tenant string, headers map[string]string) (int, []byte, http.Header) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, second.URL+"/v1/explorer/flow-snapshots/"+initial.FlowPaging.SnapshotID+"/csv", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-Probectl-Tenant", tenant)
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		response, err := second.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body, response.Header
	}
	status, data, headers := download(red.ID, nil)
	if status != http.StatusOK {
		t.Fatalf("CSV %d: %.600s", status, data)
	}
	if headers.Get("X-Probectl-SHA256") != hex.EncodeToString(crypto.Hash(data)) || headers.Get("Content-Length") != strconv.Itoa(len(data)) {
		t.Fatal("CSV length/digest mismatch")
	}
	parse := csv.NewReader(bytes.NewReader(data))
	records, err := parse.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 50002 || records[0][0] != "record_type" || records[len(records)-1][0] != "totals" || records[len(records)-1][2] != totals {
		t.Fatal("CSV selected groups/global totals incomplete")
	}
	for i, row := range records[1 : len(records)-1] {
		port := 50000 - i
		if row[0] != "detail" || row[1] != strconv.Itoa(port) || row[2] != strconv.FormatUint(9007199254740993+uint64(port-1), 10) {
			t.Fatalf("CSV row%d changed or rounded", i)
		}
	}
	for _, test := range []struct {
		tenant string
		header map[string]string
		status int
	}{{blue.ID, nil, http.StatusNotFound}, {red.ID, map[string]string{"X-QA-Other-Owner": "true"}, http.StatusNotFound}, {red.ID, map[string]string{testWithholdPermissionsHeader: permFlowRead}, http.StatusForbidden}} {
		status, _, h := download(test.tenant, test.header)
		if status != test.status || h.Get("X-Probectl-SHA256") != "" {
			t.Fatalf("CSV denial not closed: %d", status)
		}
	}
	out.Reset()
	errs.Reset()
	code = cli.RunWithStdin([]string{"--json", "explorer", "snapshot-csv", initial.FlowPaging.SnapshotID}, func(key string) string {
		switch key {
		case "PROBECTL_API_URL":
			return second.URL
		case "PROBECTL_CA_FILE":
			return ca
		case "PROBECTL_TENANT":
			return red.ID
		}
		return ""
	}, strings.NewReader(""), &out, &errs)
	if code != 0 || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("CLI CSV did not match snapshot: code%d err%.400s", code, errs.String())
	}
	if source.queries.Load() != 1 {
		t.Fatal("CSV reran source statistics")
	}
	if _, err := admin.Exec(ctx, `CREATE OR REPLACE FUNCTION public.probectl_qa_beta_csv_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='flow.snapshot.csv_export' THEN RAISE EXCEPTION 'QA CSV audit append refused'; END IF; RETURN NEW; END $$; DROP TRIGGER IF EXISTS probectl_qa_beta_csv_audit_fault ON audit_events; CREATE TRIGGER probectl_qa_beta_csv_audit_fault BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.probectl_qa_beta_csv_audit_fault()`); err != nil {
		t.Fatal(err)
	}
	dropFault := func() {
		t.Helper()
		if _, err := admin.Exec(context.Background(), `DROP TRIGGER IF EXISTS probectl_qa_beta_csv_audit_fault ON audit_events; DROP FUNCTION IF EXISTS public.probectl_qa_beta_csv_audit_fault()`); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(dropFault)
	if status, body, h := download(red.ID, nil); status != http.StatusServiceUnavailable || h.Get("X-Probectl-SHA256") != "" || bytes.HasPrefix(body, []byte("record_type")) {
		t.Fatalf("failed CSV audit sent data/status%d", status)
	}
	dropFault()
	// A damaged final chunk must refuse before any successful CSV headers,
	// even after the first45k rows have been privately prepared.
	if _, err := objects.DeletePrefix(ctx, "tenant/"+red.ID+"/flow-explorer/snapshots/"+initial.FlowPaging.SnapshotID+"/10"); err != nil {
		t.Fatal(err)
	}
	if status, body, h := download(red.ID, nil); status != http.StatusServiceUnavailable || h.Get("X-Probectl-SHA256") != "" || bytes.HasPrefix(body, []byte("record_type")) {
		t.Fatalf("partial CSV escaped a bad final chunk: %d", status)
	}
	proveFlowComparisonSnapshot(t, first, second, source, red.ID, blue.ID, at, ca)
	proveFlowQueryViewAPI(t, first, second, source, red.ID, blue.ID, at, ca)
	proveNativeMCPFlowTLS(t, admin, pool, objects, engine, source, red.ID, blue.ID, at)
}

func proveFlowComparisonSnapshot(t *testing.T, first, second *httptest.Server, source *snapshotAPISource, red, blue string, at time.Time, ca string) {
	t.Helper()
	ctx := t.Context()
	previous := make([]flowstore.Row, 50001)
	for i := 0; i < 50000; i++ {
		previous[i] = flowstore.Row{TenantID: red, AgentID: "qa-collector", Exporter: "192.0.2.1", TS: at.Add(-2 * time.Hour), SrcAddr: "198.51.100.1", DstAddr: "203.0.113.1", SrcPort: uint16(i + 1), DstPort: 443, BytesScaled: 9007199254740992 + uint64(i), PacketsScaled: 1}
	}
	previous[50000] = previous[0]
	previous[50000].SrcPort = 61000
	previous[50000].BytesScaled = ^uint64(0) - 1
	if err := source.Insert(ctx, previous); err != nil {
		t.Fatal(err)
	}
	request := func(server *httptest.Server, path, tenant string, body any, headers map[string]string) (int, []byte) {
		t.Helper()
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Probectl-Tenant", tenant)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	query := ai.ExplorerQuery{Question: "Both periods at full group reach", Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{From: at.Add(-time.Hour), To: at.Add(time.Hour), GroupBy: []string{"src_port"}, View: "table", BucketSeconds: 3600, RowLimit: 50000, PageSize: 4999, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "packets", Calculation: "total", Role: "secondary"}, {Measure: "flows", Calculation: "total", Role: "secondary"}, {Measure: "bps", Calculation: "avg", Role: "secondary"}}}}
	status, body := request(first, "/v1/explorer/compare", red, explorerComparisonRequest{Query: query, PreviousFrom: at.Add(-3 * time.Hour), PreviousTo: at.Add(-time.Hour)}, nil)
	if status != http.StatusOK {
		t.Fatalf("comparison create %d %.600s", status, body)
	}
	var page explorerComparisonResult
	if err := json.Unmarshal(body, &page); err != nil {
		t.Fatal(err)
	}
	if page.FlowPaging == nil || page.FlowPaging.SelectedRows != 50000 || !page.FlowPaging.More || page.Flow == nil {
		t.Fatal("comparison reach was reduced by metric count")
	}
	initial := page
	beforeQueries := source.queries.Load()
	late := previous[0]
	late.TS = at
	late.SrcPort = 62000
	late.BytesScaled = ^uint64(0)
	if err := source.Insert(ctx, []flowstore.Row{late}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	currentTotal, previousTotal := page.Flow.Current.Totals["bytes:total"], page.Flow.Previous.Totals["bytes:total"]
	for {
		if page.FlowPaging.Offset != len(seen) || page.Flow.Current.Totals["bytes:total"] != currentTotal || page.Flow.Previous.Totals["bytes:total"] != previousTotal {
			t.Fatal("comparison page changed global meaning")
		}
		groups := map[string]int{}
		for _, row := range page.Rows {
			if row.Other {
				continue
			}
			port := row.Group["src_port"]
			groups[port]++
			if port == "60000" && row.DeltaState != "missing_previous" || port == "61000" && row.DeltaState != "missing_current" {
				t.Fatal("missing period fabricated as zero")
			}
			if port != "60000" && port != "61000" && row.Measure == "bytes:total" && (row.DeltaExact == nil || *row.DeltaExact != "1") {
				t.Fatalf("exact delta rounded: %+v", row)
			}
		}
		for port, count := range groups {
			if seen[port] || count != 4 || port == "62000" {
				t.Fatalf("comparison duplicate/metric/late group %s %d", port, count)
			}
			seen[port] = true
		}
		if !page.FlowPaging.More {
			break
		}
		continuation := map[string]any{"query": map[string]any{"source": "flow", "flow": map[string]string{"cursor": page.FlowPaging.NextCursor}}}
		status, body = request(second, "/v1/explorer/compare", red, continuation, nil)
		if status != http.StatusOK {
			t.Fatalf("comparison resume %d %.600s", status, body)
		}
		page = explorerComparisonResult{}
		if err := json.Unmarshal(body, &page); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 50000 || !seen["60000"] || !seen["61000"] || source.queries.Load() != beforeQueries {
		t.Fatal("comparison paging lost membership or reran source")
	}
	continuation := map[string]any{"query": map[string]any{"source": "flow", "flow": map[string]string{"cursor": initial.FlowPaging.NextCursor}}}
	for _, test := range []struct {
		tenant  string
		headers map[string]string
		status  int
	}{{blue, nil, http.StatusNotFound}, {red, map[string]string{"X-QA-Other-Owner": "true"}, http.StatusNotFound}, {red, map[string]string{testWithholdPermissionsHeader: permFlowRead}, http.StatusForbidden}} {
		if status, _ := request(second, "/v1/explorer/compare", test.tenant, continuation, test.headers); status != test.status {
			t.Fatalf("comparison continuation crossed scope/permission: %d", status)
		}
	}
	singleCursor := map[string]any{"source": "flow", "flow": map[string]string{"cursor": initial.FlowPaging.NextCursor}}
	if status, _ := request(second, "/v1/explorer/query", red, singleCursor, nil); status != http.StatusUnprocessableEntity {
		t.Fatalf("comparison cursor crossed endpoint: %d", status)
	}
	continuation["previous_from"] = at.Add(-3 * time.Hour)
	if status, _ := request(second, "/v1/explorer/compare", red, continuation, nil); status != http.StatusUnprocessableEntity {
		t.Fatalf("comparison cursor accepted bounds override: %d", status)
	}
	delete(continuation, "previous_from")
	encoded, _ := json.Marshal(continuation)
	getenv := func(key string) string {
		switch key {
		case "PROBECTL_API_URL":
			return second.URL
		case "PROBECTL_CA_FILE":
			return ca
		case "PROBECTL_TENANT":
			return red
		}
		return ""
	}
	var out, errs bytes.Buffer
	if code := cli.RunWithStdin([]string{"--json", "explorer", "compare", "--body-file", "-"}, getenv, bytes.NewReader(encoded), &out, &errs); code != 0 || !strings.Contains(out.String(), `"offset": 4999`) {
		t.Fatalf("CLI comparison cursor failed %d %.400s", code, errs.String())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, second.URL+"/v1/explorer/flow-snapshots/"+initial.FlowPaging.SnapshotID+"/csv", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Probectl-Tenant", red)
	response, err := second.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("comparison CSV %d %.600s", response.StatusCode, data)
	}
	if response.Header.Get("X-Probectl-SHA256") != hex.EncodeToString(crypto.Hash(data)) || response.ContentLength != int64(len(data)) {
		t.Fatal("comparison CSV integrity")
	}
	parser := csv.NewReader(bytes.NewReader(data))
	if _, err := parser.Read(); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	totals := 0
	others := 0
	for {
		record, err := parser.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		switch record[0] {
		case "detail":
			counts[record[1]]++
		case "totals":
			totals++
		case "other":
			others++
		default:
			t.Fatal("unexpected CSV record kind")
		}
	}
	if len(counts) != 50000 || totals != 4 || others != 4 {
		t.Fatalf("comparison CSV incomplete %d/%d/%d", len(counts), totals, others)
	}
	for port, n := range counts {
		if n != 4 || !seen[port] {
			t.Fatal("comparison CSV membership changed")
		}
	}
	out.Reset()
	errs.Reset()
	if code := cli.RunWithStdin([]string{"explorer", "snapshot-csv", initial.FlowPaging.SnapshotID}, getenv, strings.NewReader(""), &out, &errs); code != 0 || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("CLI comparison CSV changed: %d %.400s", code, errs.String())
	}
	if source.queries.Load() != beforeQueries {
		t.Fatal("comparison CSV/CLI reran source")
	}
}

func proveFlowQueryViewAPI(t *testing.T, first, second *httptest.Server, source *snapshotAPISource, red, blue string, at time.Time, ca string) {
	t.Helper()
	const root = "/v1/explorer/flow-views"
	request := func(server *httptest.Server, tenant, method, path string, body any, headers map[string]string) (int, []byte) {
		t.Helper()
		var encoded []byte
		var err error
		if body != nil {
			encoded, err = json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
		}
		req, err := http.NewRequestWithContext(t.Context(), method, server.URL+path, bytes.NewReader(encoded))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Probectl-Tenant", tenant)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		response, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, data
	}
	definition := flow.QueryViewDefinition{Name: "RED-ONLY-NATIVE-VIEW", Visibility: "private", Labels: []string{"edge"}, Time: flow.QueryViewTime{Mode: "absolute"}, Plan: flow.QueryPlan{From: at.Add(-time.Hour), To: at.Add(time.Hour), View: "matrix", GroupBy: []string{"src_addr", "src_port", "protocol", "exporter", "in_if", "vlan", "dscp", "src_asn"}, MatrixWith: []string{"dst_addr", "dst_port", "transport", "next_hop", "out_if", "net_type", "tcp_flags", "dst_country"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "raw_bytes", Op: flow.QueryLess, Values: []string{"9007199254740993"}}}}}}
	definition.Display = &flow.QueryViewDisplay{TimeStyle: "horizon", PercentBasis: "visible", HorizonScale: "lane", TotalOverlay: true, LogMetrics: []string{"bytes:total"}, SyncAxes: true, OneChartPerSeries: true, ChartsPerRow: 4, ChartHeight: "short"}
	status, data := request(first, red, http.MethodPost, root, saveFlowViewRequest{Definition: definition}, nil)
	if status != http.StatusCreated {
		t.Fatalf("view create %d %.600s", status, data)
	}
	var view flow.SavedQueryView
	if err := json.Unmarshal(data, &view); err != nil {
		t.Fatal(err)
	}
	if view.Version != "1" || len(view.Definition.Plan.GroupBy) != 8 || len(view.Definition.Plan.MatrixWith) != 8 {
		t.Fatal("saved view grammar truncated")
	}
	path := root + "/" + view.ID
	status, data = request(second, red, http.MethodGet, path, nil, nil)
	if status != http.StatusOK || !bytes.Contains(data, []byte("9007199254740993")) {
		t.Fatal("view did not survive replica boundary")
	}
	var displayReload flow.SavedQueryView
	if json.Unmarshal(data, &displayReload) != nil || displayReload.Definition.Display == nil || displayReload.Definition.Display.TimeStyle != "horizon" || displayReload.Definition.Display.PercentBasis != "visible" || displayReload.Definition.Display.HorizonScale != "lane" || !displayReload.Definition.Display.TotalOverlay || displayReload.Definition.Display.ChartsPerRow != 4 || !displayReload.Definition.Display.SyncAxes {
		t.Fatal("display lost across API replicas")
	}
	encodedDefinition, _ := json.Marshal(definition)
	var injected map[string]any
	if err := json.Unmarshal(encodedDefinition, &injected); err != nil {
		t.Fatal(err)
	}
	injected["display"] = map[string]any{"tenant_id": blue, "total_overlay": true}
	status, rejected := request(first, red, http.MethodPost, root, map[string]any{"definition": injected}, nil)
	if status != http.StatusBadRequest || !bytes.Contains(rejected, []byte(`"code":"bad_request"`)) {
		t.Fatalf("unknown display field was not strictly rejected: status%d %.500s", status, rejected)
	}
	for tenant, count := range map[string]int{red: 1, blue: 0} {
		status, data := request(first, tenant, http.MethodGet, root, nil, nil)
		var page flow.QueryViewPage
		if status != http.StatusOK || json.Unmarshal(data, &page) != nil || len(page.Items) != count {
			t.Fatal("rejected scope override changed a tenant's saved views")
		}
	}
	other := map[string]string{"X-QA-Other-Owner": "true"}
	if status, _ := request(second, red, http.MethodGet, path, nil, other); status != http.StatusNotFound {
		t.Fatal("private view escaped owner")
	}
	for _, test := range []struct {
		method, path string
		body         any
	}{{http.MethodGet, path, nil}, {http.MethodPut, path, saveFlowViewRequest{Version: "1", Definition: definition}}, {http.MethodDelete, path + "?version=1", nil}, {http.MethodPut, path + "/preferences", map[string]any{"favorite": true}}, {http.MethodPost, path + "/query", nil}} {
		status, data := request(second, blue, test.method, test.path, test.body, nil)
		if status != http.StatusNotFound || bytes.Contains(data, []byte(definition.Name)) {
			t.Fatalf("view foreign route escaped %s %d", test.method, status)
		}
	}
	if status, data := request(second, blue, http.MethodGet, root, nil, nil); status != http.StatusOK || bytes.Contains(data, []byte(view.ID)) {
		t.Fatal("view list crossed tenant")
	}
	// Share configuration explicitly; ownership remains unchanged. Simplify only
	// the execution plan after proving the complete8+8 query roundtrip above.
	definition.Visibility = "tenant"
	definition.Plan = flow.QueryPlan{From: at.Add(-time.Hour), To: at.Add(time.Hour), View: "table", GroupBy: []string{"src_addr"}, RowLimit: 2, PageSize: 2, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	status, data = request(first, red, http.MethodPut, path, saveFlowViewRequest{Version: "1", Definition: definition}, nil)
	if status != http.StatusOK {
		t.Fatalf("share view %d %.600s", status, data)
	}
	if status, _ := request(second, red, http.MethodGet, path, nil, other); status != http.StatusOK {
		t.Fatal("explicit same-tenant share unavailable")
	}
	if status, _ := request(second, red, http.MethodPut, path, saveFlowViewRequest{Version: "2", Definition: definition}, other); status != http.StatusNotFound {
		t.Fatal("shared reader acquired update ownership")
	}
	if status, _ := request(second, red, http.MethodPut, path+"/preferences", map[string]any{"favorite": true}, other); status != http.StatusNoContent {
		t.Fatal("shared reader private favorite failed")
	}
	status, data = request(second, red, http.MethodGet, path, nil, nil)
	if status != http.StatusOK {
		t.Fatal("view owner get failed")
	}
	var own flow.SavedQueryView
	if err := json.Unmarshal(data, &own); err != nil || own.Favorite {
		t.Fatal("private favorite crossed users")
	}
	for _, permission := range []string{permAIQuery, permFlowRead} {
		if status, _ := request(second, red, http.MethodPost, path+"/query", nil, map[string]string{testWithholdPermissionsHeader: permission}); status != http.StatusForbidden {
			t.Fatal("view execution bypassed source authorization")
		}
	}
	if status, _ := request(second, red, http.MethodPost, root, saveFlowViewRequest{Definition: definition}, map[string]string{testWithholdPermissionsHeader: permFlowViewsWrite}); status != http.StatusForbidden {
		t.Fatal("view read grants configuration write")
	}
	status, data = request(second, red, http.MethodPost, path+"/query", nil, nil)
	if status != http.StatusOK {
		t.Fatalf("view execute %d %.600s", status, data)
	}
	var result explorerResult
	if err := json.Unmarshal(data, &result); err != nil || result.FlowPaging == nil || result.Flow == nil || len(result.Flow.Rows) != 1 || result.Flow.Rows[0].Group["src_addr"] != "198.51.100.1" {
		t.Fatal("saved query did not use shared authorized native execution")
	}
	// Per-bucket totals are frozen with every page, not reconstructed from
	// selected group/Other cardinalities or recalculated by another replica.
	chartPlan := definition.Plan
	chartPlan.View, chartPlan.GroupBy, chartPlan.RowLimit, chartPlan.PageSize, chartPlan.BucketSeconds = "line", []string{"src_port"}, 350, 7, 3600
	chartPlan.Metrics = []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}, {Measure: "unique_src", Calculation: "total", Role: "secondary"}}
	status, data = request(first, red, http.MethodPost, "/v1/explorer/query", ai.ExplorerQuery{Question: "Verify frozen source total buckets", Source: ai.ExplorerFlow, Flow: &chartPlan}, nil)
	var chart explorerResult
	if status != http.StatusOK || json.Unmarshal(data, &chart) != nil || chart.Flow == nil || chart.FlowPaging == nil || chart.FlowPaging.NextCursor == "" || len(chart.Flow.TotalSeries) != 1 {
		t.Fatalf("chart total source snapshot %d %.600s", status, data)
	}
	total := chart.Flow.TotalSeries[0]
	if total.Other || len(total.Group) != 0 || total.Metrics["unique_src:total"] != "1" || total.Metrics["bytes:total"] != chart.Flow.Totals["bytes:total"] {
		t.Fatalf("incorrect source total: %+v", total)
	}
	frozenTotals, _ := json.Marshal(chart.Flow.TotalSeries)
	beforeQueries := source.queries.Load()
	late := flowstore.Row{TenantID: red, AgentID: "qa-total-late", Exporter: "192.0.2.1", TS: at, SrcAddr: "198.51.100.1", DstAddr: "203.0.113.1", SrcPort: 64000, BytesScaled: ^uint64(0), PacketsScaled: 1}
	if err := source.Insert(t.Context(), []flowstore.Row{late}); err != nil {
		t.Fatal(err)
	}
	continuation := map[string]any{"source": "flow", "flow": map[string]string{"cursor": chart.FlowPaging.NextCursor}}
	status, data = request(second, red, http.MethodPost, "/v1/explorer/query", continuation, nil)
	var resumed explorerResult
	if status != http.StatusOK || json.Unmarshal(data, &resumed) != nil || resumed.Flow == nil {
		t.Fatalf("total replica continuation %d %.600s", status, data)
	}
	afterTotals, _ := json.Marshal(resumed.Flow.TotalSeries)
	if !bytes.Equal(afterTotals, frozenTotals) || source.queries.Load() != beforeQueries {
		t.Fatal("late ingest/replica paging changed total series or reran source")
	}
	for _, deny := range []struct {
		tenant  string
		headers map[string]string
		code    int
	}{{blue, nil, http.StatusNotFound}, {red, other, http.StatusNotFound}, {red, map[string]string{testWithholdPermissionsHeader: permFlowRead}, http.StatusForbidden}} {
		status, data = request(second, deny.tenant, http.MethodPost, "/v1/explorer/query", continuation, deny.headers)
		if status != deny.code || bytes.Contains(data, []byte("total_series")) {
			t.Fatalf("total header escaped denied continuation: %d", status)
		}
	}
	encoded, _ := json.Marshal(continuation)
	var cliTotals, cliErrors bytes.Buffer
	code := cli.RunWithStdin([]string{"--json", "explorer", "query", "--body-file", "-"}, func(key string) string {
		switch key {
		case "PROBECTL_API_URL":
			return second.URL
		case "PROBECTL_CA_FILE":
			return ca
		case "PROBECTL_TENANT":
			return red
		}
		return ""
	}, bytes.NewReader(encoded), &cliTotals, &cliErrors)
	var cliPage explorerResult
	if code != 0 || json.Unmarshal(cliTotals.Bytes(), &cliPage) != nil || cliPage.Flow == nil {
		t.Fatalf("CLI total continuation %d %.400s", code, cliErrors.String())
	}
	cliFrozen, _ := json.Marshal(cliPage.Flow.TotalSeries)
	if !bytes.Equal(cliFrozen, frozenTotals) || source.queries.Load() != beforeQueries {
		t.Fatal("CLI changed frozen total series or reran source")
	}
	if status, _ := request(second, red, http.MethodPost, path+"/query", map[string]any{"tenant_id": blue}, nil); status != http.StatusUnprocessableEntity {
		t.Fatal("view execution override accepted")
	}
	if status, data := request(second, red, http.MethodGet, root+"?tab=recents", nil, nil); status != http.StatusOK || !bytes.Contains(data, []byte(view.ID)) {
		t.Fatal("view run absent from private recents")
	}
	// Exercise every new named CLI operation against the same TLS/PG service.
	env := func(key string) string {
		switch key {
		case "PROBECTL_API_URL":
			return second.URL
		case "PROBECTL_CA_FILE":
			return ca
		case "PROBECTL_TENANT":
			return blue
		}
		return ""
	}
	invoke := func(command, id string, body any, query ...string) []byte {
		t.Helper()
		args := []string{"--json", "explorer", command}
		if id != "" {
			args = append(args, id)
		}
		for _, value := range query {
			args = append(args, "--query", value)
		}
		var encoded []byte
		if body != nil {
			encoded, _ = json.Marshal(body)
			args = append(args, "--body-file", "-")
		}
		var out, errs bytes.Buffer
		if code := cli.RunWithStdin(args, env, bytes.NewReader(encoded), &out, &errs); code != 0 {
			t.Fatalf("CLI view %s %d %.600s", command, code, errs.String())
		}
		return out.Bytes()
	}
	definition.Name = "BLUE-ONLY-CLI-VIEW"
	definition.Visibility = "private"
	definition.Plan.View = "line"
	data = invoke("view-create", "", saveFlowViewRequest{Definition: definition})
	var cliView flow.SavedQueryView
	if err := json.Unmarshal(data, &cliView); err != nil {
		t.Fatal(err)
	}
	if data := invoke("view-list", "", nil); !bytes.Contains(data, []byte(cliView.ID)) || bytes.Contains(data, []byte(view.ID)) {
		t.Fatal("CLI view list crossed boundary")
	}
	if data := invoke("view-get", cliView.ID, nil); !bytes.Contains(data, []byte(`"version": "1"`)) {
		t.Fatal("CLI view version not exact text")
	}
	if data := invoke("view-get", cliView.ID, nil); !bytes.Contains(data, []byte(`"charts_per_row": 4`)) || !bytes.Contains(data, []byte(`"total_overlay": true`)) {
		t.Fatal("CLI lost saved display settings")
	}
	invoke("view-favorite", cliView.ID, map[string]any{"favorite": true})
	definition.Description = "CLI update complete definition"
	invoke("view-update", cliView.ID, saveFlowViewRequest{Version: "1", Definition: definition})
	var cliViewRun explorerResult
	if err := json.Unmarshal(invoke("view-run", cliView.ID, nil), &cliViewRun); err != nil || cliViewRun.Flow == nil || len(cliViewRun.Flow.TotalSeries) != 1 || cliViewRun.Flow.TotalSeries[0].Metrics["bytes:total"] != "987654321" {
		t.Fatalf("CLI own-tenant total series missing: %+v %v", cliViewRun.Flow, err)
	}
	invoke("view-delete", cliView.ID, nil, "version=2")
	if status, _ := request(second, blue, http.MethodGet, root+"/"+cliView.ID, nil, nil); status != http.StatusNotFound {
		t.Fatal("CLI deleted view survived")
	}
	// Both periods go through the comparison snapshot path as well.
	definition.Name = "RED-ONLY-NATIVE-VIEW"
	definition.Comparison = &flow.QueryViewComparison{Mode: "absolute", From: at.Add(-3 * time.Hour), To: at.Add(-time.Hour)}
	if status, _ := request(first, red, http.MethodPut, path, saveFlowViewRequest{Version: "2", Definition: definition}, nil); status != http.StatusOK {
		t.Fatal("view comparison update failed")
	}
	status, data = request(second, red, http.MethodPost, path+"/query", nil, nil)
	var comparison explorerComparisonResult
	if status != http.StatusOK || json.Unmarshal(data, &comparison) != nil || comparison.FlowPaging == nil || comparison.Flow == nil {
		t.Fatalf("view comparison execute %d %.500s", status, data)
	}
	for _, period := range []*flowstore.PlanResult{&comparison.Flow.Current, &comparison.Flow.Previous} {
		if len(period.TotalSeries) != 1 || period.TotalSeries[0].Metrics["bytes:total"] != period.Totals["bytes:total"] {
			t.Fatalf("comparison frozen total series missing: %+v", period.TotalSeries)
		}
	}
	if status, _ := request(second, red, http.MethodDelete, path+"?version=3", nil, nil); status != http.StatusNoContent {
		t.Fatal("view API delete failed")
	}
}
