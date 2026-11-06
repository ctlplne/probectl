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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

type roleSnapshotObjects struct {
	objectstore.Store
	reads    atomic.Int64
	afterPut func()
}

func (s *roleSnapshotObjects) Get(ctx context.Context, key string) (objectstore.Object, error) {
	s.reads.Add(1)
	return s.Store.Get(ctx, key)
}
func (s *roleSnapshotObjects) GetLimited(ctx context.Context, key string, limit int64) (objectstore.Object, error) {
	s.reads.Add(1)
	return s.Store.GetLimited(ctx, key, limit)
}
func (s *roleSnapshotObjects) Put(ctx context.Context, key, kind string, data []byte) error {
	if err := s.Store.Put(ctx, key, kind, data); err != nil {
		return err
	}
	if s.afterPut != nil {
		mutate := s.afterPut
		s.afterPut = nil
		mutate()
	}
	return nil
}

// Actual application-role Postgres/FORCE-RLS, encrypted filesystem objects,
// TLS/current bearer and both native protocols. Telemetry and sender identities
// are modeled; this does not claim a real router or ClickHouse execution.
func TestInterfaceRoleFrozenObjectsKeepWholePagesCSVAndCurrentAuthority(t *testing.T) {
	f, rows, _, at := newRoleFlowQueryFixture(t)
	disk, err := objectstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	objects := &roleSnapshotObjects{Store: disk}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("role-frozen-fixture", base64.StdEncoding.EncodeToString(key))
	crypto.Zeroize(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	engine := tenantlife.New(f.pool, rows, objects, nil, nil, "fixture has no backups", nil)
	f.server.WithTenantLife(engine).WithFlowSnapshotStorage(FlowSnapshotStorage{
		Pool: f.pool, Objects: objects, Router: tenancy.PooledRouter{},
		Fence: tenancy.NewPostgresWriterFence(f.pool), Cache: flowsnapshot.Config{TempDir: t.TempDir()},
	})
	seedInterfaceRoleMCPConsent(f)
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	request := func(tenant, method, path string, value any) (int, []byte) {
		t.Helper()
		var body bytes.Buffer
		if value != nil {
			if err := json.NewEncoder(&body).Encode(value); err != nil {
				t.Fatal(err)
			}
		}
		req, err := http.NewRequestWithContext(t.Context(), method, socket.URL+path, &body)
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
		raw, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, raw
	}
	plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), View: "table", PageSize: 1,
		GroupBy: []string{"in_if_role", "out_if_role"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	query := ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &plan}
	create := func(tenant string) explorerResult {
		t.Helper()
		code, raw := request(tenant, http.MethodPost, "/v1/explorer/query", query)
		var got explorerResult
		if code != http.StatusOK || json.Unmarshal(raw, &got) != nil || got.Flow == nil || got.FlowPaging == nil || got.FlowPaging.SnapshotID == "" {
			t.Fatalf("role frozen result was not durably published: HTTP%d %.600s", code, raw)
		}
		return got
	}
	a, b := f.tenants[0], f.tenants[1]
	first, sibling := create(a), create(b)
	if !first.FlowPaging.More || first.FlowPaging.SelectedRows != 2 || first.Flow.Totals["bytes:total"] != "300" || first.Flow.RoleTenantID != a || len(first.Flow.RoleSources) != 1 || sibling.Flow.Totals["bytes:total"] != "900" || sibling.Flow.RoleSources[0].Role != "backbone" {
		t.Fatal("frozen role source lost complete groups, totals or paired tenant identity")
	}
	continuation := ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &flow.QueryPlan{Cursor: first.FlowPaging.NextCursor}}
	csvPath := "/v1/explorer/flow-snapshots/" + first.FlowPaging.SnapshotID + "/csv"
	code, raw := request(a, http.MethodPost, "/v1/explorer/query", continuation)
	var last explorerResult
	if code != http.StatusOK || json.Unmarshal(raw, &last) != nil || last.Flow == nil || last.FlowPaging == nil || last.FlowPaging.More || last.FlowPaging.Offset != 1 || !reflect.DeepEqual(first.Flow.RoleSources, last.Flow.RoleSources) || first.Flow.RoleDigest != last.Flow.RoleDigest {
		t.Fatal("frozen role continuation changed exact source provenance or skipped a row", code)
	}
	groups := map[string]string{}
	for _, page := range []explorerResult{first, last} {
		for _, row := range page.Flow.Rows {
			groups[row.Group["in_if_role"]+"/"+row.Group["out_if_role"]] = row.Metrics["bytes:total"]
		}
	}
	if groups["transit/other"] != "100" || groups["other/other"] != "200" {
		t.Fatal("frozen role pages changed exact complete groups", groups)
	}
	code, raw = request(a, http.MethodGet, csvPath, nil)
	records, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
	if code != http.StatusOK || err != nil || len(records) != 4 || !reflect.DeepEqual(records[0], []string{"record_type", "in_if_role", "out_if_role", "bytes:total"}) {
		t.Fatal("frozen role CSV omitted complete records", code, err, records)
	}
	csvGroups := map[string]string{}
	for _, row := range records[1:] {
		if len(row) != 4 {
			t.Fatal("frozen role CSV malformed complete cell")
		}
		if row[0] == "detail" {
			csvGroups[row[1]+"/"+row[2]] = row[3]
		}
		if row[0] == "totals" && row[3] != "300" {
			t.Fatal("frozen role CSV rounded totals")
		}
	}
	if !reflect.DeepEqual(groups, csvGroups) {
		t.Fatal("frozen role CSV changed selected groups", csvGroups)
	}
	if objects.reads.Load() == 0 {
		t.Fatal("frozen role positive did not read real encrypted objects")
	}
	native := make([]func(string, string, any, any, bool), 0, 2)
	for _, wire := range []string{"2026-07-28", "2025-11-25"} {
		call := interfaceRoleNativeTLSCaller(t, f, wire)
		native = append(native, call)
		var page mcp.NativeFlowQueryResult
		call(a, "flow_explorer_page", map[string]any{"cursor": first.FlowPaging.NextCursor}, &page, true)
		if string(page.Flow.RoleTenantID) != a || len(page.Flow.RoleSources) != 1 || string(page.Flow.RoleSources[0].InterfaceID) != f.interfaceID || string(page.Flow.RoleDigest) != first.Flow.RoleDigest {
			t.Fatal("native frozen page changed exact canonical role provenance")
		}
		var exported mcp.NativeFlowCSVResult
		call(a, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: first.FlowPaging.SnapshotID}, &exported, true)
		if exported.TotalRecords != 3 || len(exported.Records) != 3 || exported.SelectedGroups != 2 || len(exported.SourceSHA256) != 64 {
			t.Fatal("native frozen CSV omitted complete selected records", exported)
		}
	}
	refuse := func(tenant, marker string) {
		t.Helper()
		before := objects.reads.Load()
		for _, target := range []struct {
			method, path string
			body         any
		}{
			{http.MethodPost, "/v1/explorer/query", continuation}, {http.MethodGet, csvPath, nil},
		} {
			status, denied := request(tenant, target.method, target.path, target.body)
			if status == http.StatusOK || strings.Contains(string(denied), first.Flow.RoleDigest) || strings.Contains(string(denied), f.interfaceID) {
				t.Fatal(marker, status)
			}
		}
		for _, call := range native {
			call(tenant, "flow_explorer_page", map[string]any{"cursor": first.FlowPaging.NextCursor}, nil, false)
			call(tenant, "flow_explorer_csv", mcp.NativeFlowCSVInput{SnapshotID: first.FlowPaging.SnapshotID}, nil, false)
		}
		if objects.reads.Load() != before {
			t.Fatal("refused role authority accessed encrypted output objects", marker)
		}
	}
	refuse(b, "foreign tenant read a frozen role result")
	for _, permission := range []string{"entities.read", "metrics.read", "events.read"} {
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM role_permissions WHERE tenant_id=$1 AND role_id=$2 AND permission_key=$3`, a, f.roles[a], permission)
			return err
		})
		refuse(a, "frozen role output ignored current source grant withdrawal")
		f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
			return (store.Roles{}).AddPermission(ctx, sc, f.roles[a], permission)
		})
	}
	f.peer(a, 64500)
	refuse(a, "frozen role output survived changed current source authority")
	if got := create(b); got.Flow.Totals["bytes:total"] != "900" || got.Flow.RoleSources[0].Role != "backbone" {
		t.Fatal("role source withdrawal damaged sibling frozen authority")
	}
	f.peer(a, 64496)
	objects.afterPut = func() { f.peer(a, 64500) }
	if status, _ := request(a, http.MethodPost, "/v1/explorer/query", query); status == http.StatusOK {
		t.Fatal("role result published after source changed during object upload")
	}
	if objects.afterPut != nil {
		t.Fatal("role publication control never reached actual object upload")
	}
}
