// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

// Real production source-builder/stdio services and PG/FS, with reference
// memory telemetry. This does not claim release-binary main/CH/sender proof.
func TestMCPStdioNativeSourcesUseSharedPrivateResultsAndLibraries(t *testing.T) {
	admin := setupMCPStdioDB(t)
	ctx := t.Context()
	db := admin
	var err error
	if dsn := os.Getenv("PROBECTL_FLOW_FILTER_TEST_DATABASE_URL"); dsn != "" {
		db, err = store.Open(ctx, dsn, 5, 0, 5*time.Second)
		if err != nil {
			t.Fatal("runtime database configuration invalid")
		}
		t.Cleanup(db.Close)
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("qa-stdio-only", base64.StdEncoding.EncodeToString(key))
	crypto.Zeroize(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	cfg := &config.Config{FlowStoreMode: "memory", TSDBMode: "memory", ObjectStoreDir: t.TempDir(), MCPRatePerMin: 1000, FairnessQueryConcurrency: 2, FairnessQueriesPerMin: 200, FairnessTenantIdleTTL: time.Hour}
	cfg.FlowSnapshotLifetime = 2 * time.Minute
	cfg.FlowMCPSourceBytes, cfg.FlowMCPWireBytes = 48<<20, 160<<20
	cfg.FlowMCPResultNodes, cfg.FlowMCPCSVPageBytes = 5<<20, 3<<20
	paths := pathstore.NewMemory()
	t.Cleanup(func() { _ = paths.Close() })
	first, closeFirst, err := buildMCPFlowSources(cfg, quietLogger(), db, paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeFirst)
	second, closeSecond, err := buildMCPFlowSources(cfg, quietLogger(), db, paths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeSecond)
	objects, err := objectstore.NewFS(cfg.ObjectStoreDir)
	if err != nil {
		t.Fatal(err)
	}
	type identity struct{ tenant, slug, user, token string }
	create := func(label string) identity {
		t.Helper()
		tenant, err := store.NewTenants(admin.Pool()).Create(ctx, fmt.Sprintf("native-stdio-%s-%d", label, time.Now().UnixNano()), label)
		if err != nil {
			t.Fatal(err)
		}
		id := identity{tenant: tenant.ID, slug: tenant.Slug}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			attestation, err := tenantlife.New(admin.Pool(), first.Flow, objects, nil, nil, "Local fixture has no backups", quietLogger()).Erase(cleanup, tenant.ID, tenant.Slug, "qa-native-stdio")
			if err != nil || !attestation.Complete {
				t.Errorf("own native stdio cleanup: %v", err)
			}
		})
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			user, err := (store.Users{}).Create(ctx, sc, label+"@example.test", label)
			if err != nil {
				return err
			}
			id.user = user.ID
			role, err := (store.Roles{}).Create(ctx, sc, label, label, "")
			if err != nil {
				return err
			}
			for _, perm := range []string{"ai.query", "flow.read", "flow.filters.write", "flow.views.write"} {
				if err := (store.Roles{}).AddPermission(ctx, sc, role.ID, perm); err != nil {
					return err
				}
			}
			return (store.RoleBindings{}).Bind(ctx, sc, "user", id.user, role.ID)
		}); err != nil {
			t.Fatal(err)
		}
		if err := tenancy.InProvider(ctx, admin.Pool(), func(ctx context.Context, q tenancy.Querier) error {
			_, err := q.Exec(ctx, `INSERT INTO tenant_governance(tenant_id,ai_remote_egress) VALUES($1,true)`, id.tenant)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		id.token, err = auth.RandomToken()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.NewMCPTokens(db.Pool()).CreateWithLifetime(ctx, id.tenant, id.user, label, crypto.Hash([]byte(id.token)), time.Now().Add(time.Hour), nil); err != nil {
			t.Fatal(err)
		}
		return id
	}
	red, blue := create("red"), create("blue")
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	rows := []flowstore.Row{{TenantID: red.tenant, TS: at, SrcPort: 1, Protocol: "STDIO_RED", BytesScaled: 9007199254740993}, {TenantID: red.tenant, TS: at, SrcPort: 2, Protocol: "STDIO_RED", BytesScaled: 9007199254740994}, {TenantID: blue.tenant, TS: at, SrcPort: 7, Protocol: "STDIO_BLUE", BytesScaled: 987654321}}
	for _, source := range []control.AISources{first, second} {
		if err := source.Flow.Insert(ctx, rows); err != nil {
			t.Fatal(err)
		}
	}
	a := newMCPStdioRuntime(cfg, quietLogger(), db, paths, first)
	b := newMCPStdioRuntime(cfg, quietLogger(), db, paths, second)
	authenticator := control.NewMCPAuthenticator(db.Pool(), control.NewTenantStatusCache(db.Pool(), 0), false)
	call := func(runtime mcpStdioRuntime, id identity, name string, args, target any, wantOK bool) {
		t.Helper()
		principal, err := authenticator.Authenticate(ctx, id.token)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
		if err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if err := runtime.server.ServeAuthenticatedStdio(ctx, bytes.NewReader(append(raw, '\n')), &output, principal, func(ctx context.Context) (*auth.Principal, error) { return authenticator.Authenticate(ctx, id.token) }); err != nil {
			t.Fatal(err)
		}
		if strings.Count(output.String(), "\n") != 1 {
			t.Fatal("native stdio framing changed")
		}
		var reply struct {
			Error  json.RawMessage `json:"error"`
			Result struct {
				IsError bool            `json:"isError"`
				Data    json.RawMessage `json:"structuredContent"`
			} `json:"result"`
		}
		if err := json.Unmarshal(output.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		ok := len(reply.Error) == 0 && !reply.Result.IsError && len(reply.Result.Data) > 0
		if ok != wantOK {
			t.Fatalf("native stdio %s success%v expected%v", name, ok, wantOK)
		}
		if ok && target != nil && json.Unmarshal(reply.Result.Data, target) != nil {
			t.Fatal("native stdio projection invalid")
		}
		if !ok && len(reply.Result.Data) > 0 {
			t.Fatal("refused native stdio call exposed data")
		}
	}
	for _, id := range []identity{red, blue} {
		var proposal mcp.NativeFlowQuestionResult
		call(a, id, "flow_explorer_plan", mcp.NativeFlowQuestionInput{Question: "show bps all rows"}, &proposal, true)
		if proposal.Proposal.Status != "ready" || proposal.Proposal.Plan == nil || proposal.Proposal.Plan.RowLimit != 50000 {
			t.Fatal("actual stdio source did not expose stateless native planning")
		}
		call(b, id, "flow_explorer_plan", map[string]any{"question": "show bps", "tenant_id": id.tenant}, nil, false)
		call(b, id, "flow_explorer_plan", map[string]any{"question": "show bps", "parent": map[string]any{}}, nil, false)
		var schema mcp.NativeFlowSchemaResult
		call(a, id, "flow_explorer_schema", struct{}{}, &schema, true)
		if schema.Limits.MaxTableRows != 50000 {
			t.Fatal("stdio constructor narrowed native reach")
		}
		if schema.RenderCost.SourceBytes != cfg.FlowMCPSourceBytes || schema.RenderCost.WireBytes != cfg.FlowMCPWireBytes || schema.RenderCost.Nodes != cfg.FlowMCPResultNodes || schema.RenderCost.CSVPageBytes != cfg.FlowMCPCSVPageBytes {
			t.Fatal("actual stdio source construction ignored operator render admission")
		}
		plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), GroupBy: []string{"src_port"}, View: "table", RowLimit: 50000, PageSize: 1, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
		var result mcp.NativeFlowQueryResult
		began := time.Now()
		call(a, id, "flow_explorer_query", map[string]any{"plan": plan}, &result, true)
		if result.Paging == nil || len(result.Flow.Rows) != 1 {
			t.Fatal("native stdio shared result absent")
		}
		if result.Paging.ExpiresAt.Before(began) || result.Paging.ExpiresAt.After(time.Now().Add(cfg.FlowSnapshotLifetime+time.Second)) {
			t.Fatal("actual stdio source assembly ignored the operator snapshot lifetime")
		}
		foreign := red
		if id.tenant == red.tenant {
			foreign = blue
		}
		if id.tenant == red.tenant {
			if result.Flow.Rows[0].Metrics[0].Value != "9007199254740994" || result.Paging.SelectedRows != 2 {
				t.Fatal("stdio source lost exact own rows")
			}
			var next mcp.NativeFlowQueryResult
			call(b, id, "flow_explorer_page", map[string]any{"cursor": result.Paging.NextCursor}, &next, true)
			if next.Paging.Offset != 1 || next.Flow.Rows[0].Metrics[0].Value != "9007199254740993" {
				t.Fatal("stdio second source did not resume exact shared page")
			}
			call(b, foreign, "flow_explorer_page", map[string]any{"cursor": result.Paging.NextCursor}, nil, false)
		} else if result.Flow.Rows[0].Metrics[0].Value != "987654321" {
			t.Fatal("blue stdio source escaped own lane")
		}
		var exported mcp.NativeFlowCSVResult
		call(b, id, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: result.Paging.SnapshotID}, &exported, true)
		if exported.TotalRecords != result.Paging.SelectedRows+1 {
			t.Fatal("native stdio CSV incomplete")
		}
		call(b, foreign, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: result.Paging.SnapshotID}, nil, false)
		expression := flow.QueryFilterGroup{Conditions: []flow.QueryPredicate{{Field: "src_port", Op: flow.QueryEqual, Values: []string{result.Flow.Rows[0].Group[0].Value}}}}
		var filter mcp.NativeFlowFilter
		call(a, id, "flow_filter_save", mcp.NativeFlowFilterInput{Name: "Stdio stored filter", Expression: expression}, &filter, true)
		call(b, id, "flow_filter_get", map[string]any{"id": filter.ID}, nil, true)
		call(b, foreign, "flow_filter_get", map[string]any{"id": filter.ID}, nil, false)
		plan.Filter = &flow.QueryFilterGroup{Saved: []flow.QuerySavedFilterRef{{ID: filter.ID}}}
		var view mcp.NativeFlowView
		call(a, id, "flow_view_save", flow.SaveQueryView{Definition: flow.QueryViewDefinition{Name: "Stdio stored query", Plan: plan}}, &view, true)
		var execution mcp.NativeFlowExecution
		call(b, id, "flow_view_run", map[string]any{"id": view.ID}, &execution, true)
		if execution.Query == nil || len(execution.Query.Flow.Rows) != 1 {
			t.Fatal("stdio stored view did not execute its configured source")
		}
		call(b, foreign, "flow_view_run", map[string]any{"id": view.ID}, nil, false)
	}
}
