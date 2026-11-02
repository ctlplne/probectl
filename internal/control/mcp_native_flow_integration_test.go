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
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

// Reuses the owned PG/FS fixture, but authenticates actual bearer tokens on
// TLS sockets and persists real policy/egress/call audits. Telemetry remains
// the explicitly labeled reference memory source, not release/sender proof.
func proveNativeMCPFlowTLS(t *testing.T, admin, pool *pgxpool.Pool, objects objectstore.Store, engine *tenantlife.Engine, source *snapshotAPISource, red, blue string, at time.Time) {
	t.Helper()
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		t.Run("native_mcp_"+wire, func(t *testing.T) {
			proveNativeMCPFlowTLSVersion(t, admin, pool, objects, engine, source, red, blue, at, wire)
		})
	}
}

func proveNativeMCPFlowTLSVersion(t *testing.T, admin, pool *pgxpool.Pool, objects objectstore.Store, engine *tenantlife.Engine, source *snapshotAPISource, red, blue string, at time.Time, wire string) {
	t.Helper()
	ctx := t.Context()
	type identity struct{ tenant, user, role, token, tokenID string }
	newIdentity := func(tenant, label string) identity {
		t.Helper()
		label += "-" + wire
		id := identity{tenant: tenant}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			u, err := (store.Users{}).Create(ctx, sc, label+"@example.test", label)
			if err != nil {
				return err
			}
			id.user = u.ID
			r, err := (store.Roles{}).Create(ctx, sc, label, label, "local native MCP proof")
			if err != nil {
				return err
			}
			id.role = r.ID
			for _, perm := range []string{permFlowRead, permAIQuery, permFlowFiltersWrite, permFlowViewsWrite} {
				var exists bool
				if err := sc.Q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM permissions WHERE key=$1)`, perm).Scan(&exists); err != nil {
					return err
				}
				if !exists {
					return fmt.Errorf("native MCP permission absent after migrations: %s", perm)
				}
				if err := (store.Roles{}).AddPermission(ctx, sc, r.ID, perm); err != nil {
					return err
				}
			}
			return (store.RoleBindings{}).Bind(ctx, sc, "user", id.user, id.role)
		}); err != nil {
			t.Fatal(err)
		}
		var err error
		id.token, err = auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		id.tokenID, err = store.NewMCPTokens(pool).CreateWithLifetime(ctx, tenant, id.user, label, crypto.Hash([]byte(id.token)), time.Now().Add(time.Hour), nil)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	a, b, otherOwner := newIdentity(red, "native-mcp-red"), newIdentity(blue, "native-mcp-blue"), newIdentity(red, "native-mcp-other")
	consent := func(tenant string, allowed bool) {
		t.Helper()
		if err := tenancy.InProvider(ctx, admin, func(ctx context.Context, q tenancy.Querier) error {
			_, err := q.Exec(ctx, `INSERT INTO tenant_governance (tenant_id, ai_remote_egress) VALUES ($1,$2) ON CONFLICT (tenant_id) DO UPDATE SET ai_remote_egress=excluded.ai_remote_egress`, tenant, allowed)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	consent(red, true)
	consent(blue, true)
	var nativeCores []*Server
	nativeServer := func() *mcp.Server {
		core := testServer(fakePinger{}).WithFlowStore(source).WithTenantLife(engine).
			WithFlowQueryFilters(flow.NewPostgresQueryFilterStore(pool, 0, audit.TenantRecord)).WithFlowQueryViews(flow.NewPostgresQueryViewStore(pool, 0, audit.TenantRecord)).
			WithFlowSnapshotStorage(FlowSnapshotStorage{Pool: pool, Objects: objects, Router: tenancy.PooledRouter{}, Fence: tenancy.NewPostgresWriterFence(pool), Cache: flowsnapshot.Config{TempDir: t.TempDir()}})
		core.pool = pool
		core.abac = newABACCache(pool)
		nativeCores = append(nativeCores, core)
		cfg, log := &config.Config{}, quietLog()
		server := NewMCPServerWithPolicyLoader(cfg, log, pool, pathstore.NewMemory(), 0, NewAIEgressGate(cfg, log, pool), nil, nil, core.MCPPolicyLoader(), AISources{Flow: source, NativeFlow: core})
		return server
	}
	replica := func() *httptest.Server {
		socket := httptest.NewTLSServer(nativeServer().HTTPHandler(NewMCPAuthenticator(pool, NewTenantStatusCache(pool, 0), false)))
		t.Cleanup(socket.Close)
		if wire == "2025-11-25" {
			for _, id := range []identity{a, b, otherOwner} {
				proveLegacyMCPInitializationTLS(t, socket, id.token)
			}
		}
		return socket
	}
	first, second := replica(), replica()
	call := func(socket *httptest.Server, id identity, tool string, args any, target any, wantOK bool) []byte {
		t.Helper()
		params := map[string]any{"name": tool, "arguments": args}
		if wire == "2026-07-28" {
			params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": wire, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
		}
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, socket.URL, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+id.token)
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", wire)
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", tool)
		// An untrusted tenant hint must never replace the token's own scope.
		req.Header.Set("X-Probectl-Tenant", blue)
		response, err := socket.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 128<<20+1))
		if err != nil || len(raw) > 128<<20 {
			t.Fatal("native MCP TLS response exceeded complete-wire budget")
		}
		if response.StatusCode == http.StatusUnauthorized && !wantOK {
			return nil
		}
		if response.Header.Get("Content-Type") == "text/event-stream" {
			var final []byte
			for _, line := range bytes.Split(raw, []byte{'\n'}) {
				if bytes.HasPrefix(line, []byte("data: ")) {
					final = bytes.TrimPrefix(line, []byte("data: "))
				}
			}
			if len(final) == 0 {
				t.Fatal("legacy native HTTP stream lost its final RPC frame")
			}
			raw = final
		}
		var reply struct {
			Error  json.RawMessage `json:"error"`
			Result struct {
				ResultType string                     `json:"resultType"`
				Meta       map[string]json.RawMessage `json:"_meta"`
				IsError    bool                       `json:"isError"`
				Data       json.RawMessage            `json:"structuredContent"`
				Content    []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"result"`
		}
		if err := json.Unmarshal(raw, &reply); err != nil || (response.StatusCode != http.StatusOK && (wantOK || response.StatusCode != http.StatusBadRequest)) {
			t.Fatalf("native MCP %s returned invalid HTTP/RPC response: status%d", tool, response.StatusCode)
		}
		ok := len(reply.Error) == 0 && !reply.Result.IsError && len(reply.Result.Data) > 0
		if ok != wantOK {
			t.Fatalf("native MCP %s success=%v expected%v: %.400s", tool, ok, wantOK, raw)
		}
		if !ok {
			if len(reply.Result.Data) > 0 && string(reply.Result.Data) != "null" {
				t.Fatal("refused native call exposed structured data")
			}
			return nil
		}
		if wire == "2026-07-28" && (reply.Result.ResultType != "complete" || len(reply.Result.Meta["io.modelcontextprotocol/serverInfo"]) == 0) {
			t.Fatal("actual modern TLS result lost complete metadata")
		}
		if wire == "2025-11-25" && (reply.Result.ResultType != "" || len(reply.Result.Meta) != 0) {
			t.Fatal("actual legacy TLS result inherited modern metadata")
		}
		if len(reply.Result.Content) != 1 || !bytes.Equal(bytes.TrimSpace([]byte(reply.Result.Content[0].Text)), bytes.TrimSpace(reply.Result.Data)) {
			t.Fatal("native MCP text/structured complete results disagree")
		}
		if target != nil && json.Unmarshal(reply.Result.Data, target) != nil {
			t.Fatal("native MCP typed result invalid")
		}
		return reply.Result.Data
	}
	plan := flow.QueryPlan{From: at.Add(-time.Hour).Add(123456789 * time.Nanosecond), To: at.Add(time.Hour).Add(123456789 * time.Nanosecond), GroupBy: []string{"src_port"}, View: "table", BucketSeconds: 3600, RowLimit: 50000, PageSize: 5000, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}, Filter: &flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_port", Op: flow.QueryLess, Values: []string{"50001"}}}}}
	var initial mcp.NativeFlowQueryResult
	queries := source.queries.Load()
	raw := call(first, a, "flow_explorer_query", map[string]any{"plan": plan}, &initial, true)
	if initial.Paging == nil || initial.Paging.SelectedRows != 50000 || len(initial.Flow.Rows) != 5000 || !bytes.Contains(raw, []byte(".123456789Z")) {
		t.Fatal("native TLS query lost full table reach or exact time")
	}
	page, count := initial, 0
	for {
		if page.Paging.Offset != count || page.Flow.Totals[0].Value != initial.Flow.Totals[0].Value {
			t.Fatal("native TLS paging changed frozen totals or offset")
		}
		for _, row := range page.Flow.Rows {
			port := 50000 - count
			if len(row.Group) != 1 || row.Group[0].Value != strconv.Itoa(port) || row.Metrics[0].Value != strconv.FormatUint(9007199254740993+uint64(port-1), 10) {
				t.Fatal("native TLS paging duplicated, rounded or changed a source row")
			}
			count++
		}
		if page.Paging.NextCursor == "" {
			break
		}
		next := page.Paging.NextCursor
		page = mcp.NativeFlowQueryResult{}
		call(second, a, "flow_explorer_page", map[string]any{"cursor": next}, &page, true)
	}
	if count != 50000 || source.queries.Load() != queries+1 {
		t.Fatal("native pages lost reach or reran source query")
	}
	for _, id := range []identity{b, otherOwner} {
		call(second, id, "flow_explorer_page", map[string]any{"cursor": initial.Paging.NextCursor}, nil, false)
	}
	bluePlan := plan
	bluePlan.Filter = nil
	var blueResult mcp.NativeFlowQueryResult
	call(first, b, "flow_explorer_query", map[string]any{"plan": bluePlan}, &blueResult, true)
	if len(blueResult.Flow.Rows) != 1 || blueResult.Flow.Rows[0].Group[0].Value != "65500" || blueResult.Flow.Rows[0].Metrics[0].Value != "987654321" {
		t.Fatal("native TLS query escaped token tenant scope")
	}
	var blueCSV mcp.NativeFlowCSVResult
	call(second, b, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: blueResult.Paging.SnapshotID}, &blueCSV, true)
	if blueCSV.TotalRecords != 2 || len(blueCSV.Records) != 2 || blueCSV.Records[0][1] != "65500" || blueCSV.Records[0][2] != "987654321" {
		t.Fatal("native blue CSV changed tenant data")
	}
	var comparison mcp.NativeFlowComparisonResult
	call(first, a, "flow_explorer_compare", mcp.NativeFlowCompareInput{Plan: plan, PreviousFrom: at.Add(-3 * time.Hour), PreviousTo: at.Add(-time.Hour)}, &comparison, true)
	if comparison.Paging == nil || comparison.Paging.SelectedRows != 50000 || len(comparison.Current.Rows) != 5000 || comparison.Previous.Rows[0].Metrics[0].Value != "9007199254790991" {
		t.Fatal("native TLS comparison narrowed paired frozen result")
	}
	var resumed mcp.NativeFlowComparisonResult
	call(second, a, "flow_explorer_comparison_page", map[string]any{"cursor": comparison.Paging.NextCursor}, &resumed, true)
	if resumed.Paging.Offset != 5000 || resumed.Current.Totals[0].Value != comparison.Current.Totals[0].Value || resumed.Previous.Totals[0].Value != comparison.Previous.Totals[0].Value {
		t.Fatal("native TLS comparison page changed either period")
	}
	for _, id := range []identity{b, otherOwner} {
		call(second, id, "flow_explorer_comparison_page", map[string]any{"cursor": comparison.Paging.NextCursor}, nil, false)
	}
	for _, snapshot := range []string{initial.Paging.SnapshotID, comparison.Paging.SnapshotID} {
		var rebuilt bytes.Buffer
		writer := csv.NewWriter(&rebuilt)
		offset, count := 0, 0
		var sourceHash string
		var sourceSize int64
		for {
			var page mcp.NativeFlowCSVResult
			call(second, a, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: snapshot, RecordOffset: offset}, &page, true)
			if page.RecordOffset != count || page.SelectedGroups != 50000 || page.TotalRecords != 50001 {
				t.Fatal("native CSV omitted selected groups or global totals")
			}
			if offset == 0 {
				if err := writer.Write(page.Columns); err != nil {
					t.Fatal(err)
				}
				sourceHash, sourceSize = page.SourceSHA256, page.SourceBytes
			}
			if page.SourceSHA256 != sourceHash || page.SourceBytes != sourceSize {
				t.Fatal("native CSV page changed source identity")
			}
			if err := writer.WriteAll(page.Records); err != nil {
				t.Fatal(err)
			}
			count += len(page.Records)
			if page.NextRecord == nil {
				if len(page.Records) == 0 || page.Records[len(page.Records)-1][0] != "totals" {
					t.Fatal("native CSV missing final totals")
				}
				break
			}
			if *page.NextRecord != count || count <= offset {
				t.Fatal("native CSV record continuation did not advance")
			}
			offset = *page.NextRecord
		}
		writer.Flush()
		if writer.Error() != nil || int64(rebuilt.Len()) != sourceSize || hex.EncodeToString(crypto.Hash(rebuilt.Bytes())) != sourceHash || count != 50001 {
			t.Fatal("native CSV pages did not reconstruct the complete authoritative bytes/digest")
		}
		for _, id := range []identity{b, otherOwner} {
			call(second, id, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: snapshot}, nil, false)
		}
	}
	for _, id := range []identity{a, b} {
		queriesBeforePlanning := source.queries.Load()
		var proposal mcp.NativeFlowQuestionResult
		call(first, id, "flow_explorer_plan", mcp.NativeFlowQuestionInput{Question: "show bps all rows"}, &proposal, true)
		if proposal.Proposal.Status != "ready" || proposal.Proposal.Plan == nil || proposal.Proposal.Plan.RowLimit != 50000 || source.queries.Load() != queriesBeforePlanning {
			t.Fatal("native TLS planning read telemetry or narrowed the proposal")
		}
		call(second, id, "flow_explorer_plan", map[string]any{"question": "show bps", "tenant_id": red}, nil, false)
		call(second, id, "flow_explorer_plan", map[string]any{"question": "show bps", "parent": map[string]any{}}, nil, false)
		var schema mcp.NativeFlowSchemaResult
		call(first, id, "flow_explorer_schema", struct{}{}, &schema, true)
		if schema.Limits.MaxExpandedConditions != 1000 || schema.Limits.MaxTableRows != 50000 {
			t.Fatal("native TLS registry reduced reach")
		}
		exporter := "192.0.2.1"
		if id.tenant == blue {
			exporter = "192.0.2.2"
		}
		expression := flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "exporter", Op: flow.QueryEqual, Values: []string{exporter}}}}
		var filter mcp.NativeFlowFilter
		call(first, id, "flow_filter_save", mcp.NativeFlowFilterInput{Name: "TLS saved filter", Expression: expression}, &filter, true)
		if filter.Version != "1" {
			t.Fatal("native TLS filter create revision changed")
		}
		for _, tool := range []string{"flow_filter_get", "flow_filter_list"} {
			args := map[string]any{}
			if tool == "flow_filter_get" {
				args["id"] = filter.ID
			}
			call(second, id, tool, args, nil, true)
		}
		call(second, id, "flow_filter_save", mcp.NativeFlowFilterInput{ID: filter.ID, Version: filter.Version, Name: "TLS updated filter", Expression: expression}, &filter, true)
		if filter.Version != "2" {
			t.Fatal("native TLS filter update revision changed")
		}
		savedPlan := plan
		savedPlan.RowLimit = 1
		savedPlan.PageSize = 1
		savedPlan.Filter = &flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: filter.ID}}}
		var view mcp.NativeFlowView
		call(first, id, "flow_view_save", flow.SaveQueryView{Definition: flow.QueryViewDefinition{Name: "TLS saved query", Plan: savedPlan, Display: &flow.QueryViewDisplay{TimeStyle: "horizon", HorizonScale: "lane"}}}, &view, true)
		if view.Version != "1" || view.Definition.Display.HorizonScale != "lane" {
			t.Fatal("native TLS saved definition changed")
		}
		call(second, id, "flow_view_get", map[string]any{"id": view.ID}, nil, true)
		call(second, id, "flow_view_list", mcp.NativeFlowViewListInput{}, nil, true)
		call(second, id, "flow_view_favorite", map[string]any{"id": view.ID, "favorite": true}, nil, true)
		var execution mcp.NativeFlowExecution
		call(second, id, "flow_view_run", map[string]any{"id": view.ID}, &execution, true)
		if execution.Query == nil || len(execution.Query.Flow.Rows) != 1 {
			t.Fatal("native TLS saved execution unavailable")
		}
		foreign := a
		if id.tenant == red {
			foreign = b
		}
		for _, tool := range []string{"flow_filter_get", "flow_view_get", "flow_view_run"} {
			resource := view.ID
			if tool == "flow_filter_get" {
				resource = filter.ID
			}
			call(second, foreign, tool, map[string]any{"id": resource}, nil, false)
		}
		view.Definition.Visibility = "tenant"
		call(second, id, "flow_view_save", flow.SaveQueryView{ID: view.ID, Version: view.Version, Definition: view.Definition.QueryViewDefinition()}, &view, true)
		if view.Version != "2" {
			t.Fatal("native TLS view update revision changed")
		}
		if id.tenant == red {
			call(second, otherOwner, "flow_view_get", map[string]any{"id": view.ID}, nil, true)
			call(second, otherOwner, "flow_view_delete", map[string]any{"id": view.ID, "version": view.Version}, nil, false)
		}
		call(second, id, "flow_view_delete", map[string]any{"id": view.ID, "version": view.Version}, nil, true)
		call(second, id, "flow_filter_delete", map[string]any{"id": filter.ID, "version": filter.Version}, nil, true)
	}
	consent(red, false)
	call(second, a, "flow_explorer_page", map[string]any{"cursor": initial.Paging.NextCursor}, nil, false)
	call(second, a, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: initial.Paging.SnapshotID}, nil, false)
	consent(red, true)
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(red)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.RoleBindings{}).Unbind(ctx, sc, "user", a.user, a.role)
	}); err != nil {
		t.Fatal(err)
	}
	call(second, a, "flow_explorer_page", map[string]any{"cursor": initial.Paging.NextCursor}, nil, false)
	call(second, a, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: initial.Paging.SnapshotID}, nil, false)
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(red)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		return (store.RoleBindings{}).Bind(ctx, sc, "user", a.user, a.role)
	}); err != nil {
		t.Fatal(err)
	}
	call(second, a, "flow_explorer_page", map[string]any{"cursor": initial.Paging.NextCursor}, nil, true)
	// Complete CSV verification and its immutable audit must both finish before
	// any record is published, even if the requested page is the first one.
	if _, err := admin.Exec(ctx, `CREATE OR REPLACE FUNCTION public.probectl_qa_beta_native_csv_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='flow.snapshot.csv_export' THEN RAISE EXCEPTION 'QA native CSV audit refused'; END IF; RETURN NEW; END $$; DROP TRIGGER IF EXISTS probectl_qa_beta_native_csv_audit_fault ON audit_events; CREATE TRIGGER probectl_qa_beta_native_csv_audit_fault BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION public.probectl_qa_beta_native_csv_audit_fault()`); err != nil {
		t.Fatal(err)
	}
	dropFault := func() {
		t.Helper()
		if _, err := admin.Exec(context.Background(), `DROP TRIGGER IF EXISTS probectl_qa_beta_native_csv_audit_fault ON audit_events; DROP FUNCTION IF EXISTS public.probectl_qa_beta_native_csv_audit_fault()`); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(dropFault)
	call(second, a, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: initial.Paging.SnapshotID}, nil, false)
	dropFault()
	if _, err := objects.DeletePrefix(ctx, "tenant/"+red+"/flow-explorer/snapshots/"+initial.Paging.SnapshotID+"/10"); err != nil {
		t.Fatal(err)
	}
	call(second, a, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: initial.Paging.SnapshotID}, nil, false)
	if _, err := store.NewMCPTokens(pool).RevokeByID(ctx, red, a.tokenID); err != nil {
		t.Fatal(err)
	}
	call(second, a, "flow_explorer_page", map[string]any{"cursor": initial.Paging.NextCursor}, nil, false)
	// The same process must reload a real PostgreSQL credential for every stdio
	// frame. This proves the authenticated library seam, not command source setup.
	stdioID := newIdentity(red, "native-mcp-stdio")
	authenticator := NewMCPAuthenticator(pool, NewTenantStatusCache(pool, 0), false)
	principal, err := authenticator.Authenticate(ctx, stdioID.token)
	if err != nil {
		t.Fatal(err)
	}
	inputR, inputW := io.Pipe()
	outputR, outputW := io.Pipe()
	closePipes := func() { _ = inputR.Close(); _ = inputW.Close(); _ = outputR.Close(); _ = outputW.Close() }
	defer closePipes()
	stdioCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	go func() { <-stdioCtx.Done(); closePipes() }()
	done := make(chan error, 1)
	go func() {
		defer outputW.Close()
		done <- nativeServer().ServeAuthenticatedStdio(stdioCtx, inputR, outputW, principal, func(ctx context.Context) (*auth.Principal, error) {
			return authenticator.Authenticate(ctx, stdioID.token)
		})
	}()
	decoder := json.NewDecoder(outputR)
	if wire == "2025-11-25" {
		initial, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": map[string]any{"protocolVersion": wire, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "owned-pg-client", "version": "1"}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := inputW.Write(append(initial, '\n')); err != nil {
			t.Fatal(err)
		}
		var initialized struct {
			Result struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"result"`
		}
		if decoder.Decode(&initialized) != nil || initialized.Result.ProtocolVersion != wire {
			t.Fatal("live PG stdio did not negotiate legacy revision")
		}
		if _, err := inputW.Write([]byte("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")); err != nil {
			t.Fatal(err)
		}
	}
	params := map[string]any{"name": "flow_explorer_schema", "arguments": map[string]any{}}
	if wire == "2026-07-28" {
		params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": wire, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
	}
	frame, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": params})
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 2; step++ {
		if _, err := inputW.Write(append(frame, '\n')); err != nil {
			t.Fatal(err)
		}
		var response struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if err := decoder.Decode(&response); err != nil {
			t.Fatal(err)
		}
		if step == 0 {
			if len(response.Error) > 0 || len(response.Result) == 0 || (wire == "2026-07-28" && !bytes.Contains(response.Result, []byte(`"resultType":"complete"`))) || (wire == "2025-11-25" && bytes.Contains(response.Result, []byte("resultType"))) {
				t.Fatal("live PostgreSQL stdio initial credential refused")
			}
			if _, err := store.NewMCPTokens(pool).RevokeByID(ctx, red, stdioID.tokenID); err != nil {
				t.Fatal(err)
			}
		} else if len(response.Error) == 0 || len(response.Result) > 0 {
			t.Fatal("same stdio process retained revoked real credential")
		}
	}
	if err := inputW.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	var observedQueries, observedPages, observedCSV uint64
	for _, core := range nativeCores {
		observedQueries += core.flowOperationMetrics["query"].outcomes["success"].Value()
		observedPages += core.flowOperationMetrics["page"].outcomes["success"].Value()
		observedCSV += core.flowOperationMetrics["csv_prepare"].outcomes["success"].Value()
		proveNativeFlowMetricsTLS(t, core, []string{a.token, b.token, stdioID.token}, []string{red, blue, a.user, b.user})
	}
	if observedQueries == 0 || observedPages == 0 || observedCSV == 0 {
		t.Fatal("real native query/paging/CSV services omitted process instrumentation")
	}
	for _, tenant := range []string{red, blue} {
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, sc tenancy.Scope) error {
			for _, action := range []string{"mcp.tool_call", "ai.remote_egress"} {
				var count int
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action=$1`, action).Scan(&count); err != nil {
					return err
				}
				if count == 0 {
					t.Error("native TLS proof omitted durable audit", action)
				}
			}
			return audit.TenantVerify(ctx, sc)
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func proveLegacyMCPInitializationTLS(t *testing.T, socket *httptest.Server, token string) {
	t.Helper()
	frames := []string{
		`{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"owned-pg-client","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
	}
	for index, frame := range frames {
		r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, socket.URL, strings.NewReader(frame))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("MCP-Protocol-Version", "2025-11-25")
		response, err := socket.Client().Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if err != nil || response.Header.Get("MCP-Session-Id") != "" {
			t.Fatal("legacy initialization failed or created session authority")
		}
		if index == 0 {
			var result struct {
				Result struct {
					Version string `json:"protocolVersion"`
				} `json:"result"`
			}
			if response.StatusCode != 200 || json.Unmarshal(raw, &result) != nil || result.Result.Version != "2025-11-25" {
				t.Fatal("actual PG HTTP legacy initialization version mismatch")
			}
		} else if response.StatusCode != 202 || len(raw) != 0 {
			t.Fatal("actual PG HTTP initialized notification not accepted")
		}
	}
}

func proveNativeFlowMetricsTLS(t *testing.T, core *Server, tenantTokens, privateIDs []string) {
	t.Helper()
	core.cfg.AuthMode = "session"
	core.cfg.MetricsScrapeToken = "owned-native-metrics-scrape"
	socket := httptest.NewTLSServer(core.Handler())
	defer socket.Close()
	for _, token := range append([]string{"", core.cfg.MetricsScrapeToken}, tenantTokens...) {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, socket.URL+"/metrics", nil)
		if err != nil {
			t.Fatal(err)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		response, err := socket.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
		_ = response.Body.Close()
		if readErr != nil || len(body) > 1<<20 {
			t.Fatal("bounded metrics scrape failed", readErr)
		}
		if token != core.cfg.MetricsScrapeToken {
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatal("tenant credential gained process metrics privilege")
			}
			continue
		}
		if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "# TYPE probectl_flow_explorer_query_duration_seconds histogram\n") {
			t.Fatal("actual TLS scrape omitted native metric definitions")
		}
		for _, private := range append(append([]string{}, privateIDs...), tenantTokens...) {
			if strings.Contains(string(body), private) {
				t.Fatal("process scrape exposed private native scope/credential")
			}
		}
		for _, operation := range []string{"query", "comparison", "page", "comparison_page", "csv_prepare"} {
			if !strings.Contains(string(body), "probectl_flow_explorer_"+operation+"_active 0\n") {
				t.Fatal("real native operation retained active work")
			}
		}
	}
}
