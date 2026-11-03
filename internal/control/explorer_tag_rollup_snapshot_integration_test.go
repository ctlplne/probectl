// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package control

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

// Actual PostgreSQL/ClickHouse policy reader and encrypted shared cache through
// native REST/MCP/CSV. Rows are directly seeded; release senders/bus/four stores
// remain a separate mandatory proof.
func TestExplorerTagRollupFreezesActualCompleteRetainedInputs(t *testing.T) {
	endpoint := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if endpoint == "" {
		testsupport.SkipOrFatal(t, "PROBECTL_FLOWSTORE_URL is required for tagged retained-result proof")
	}
	f := newTagImportSubjectFixture(t)
	ch, err := flowstore.NewClickHouse(endpoint, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ch.Close() })
	readerUser, reader := chtest.ProvisionReader(t, endpoint, "fx3_snapshot_reader")
	ch.WithTenantScoping(true).WithReader(reader)
	if err := ch.EnsureReaderRowPolicy(t.Context(), readerUser); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, tenant := range []string{f.a, f.b} {
			if _, err := ch.DeleteTenant(ctx, tenant); err != nil {
				t.Error(err)
			}
		}
	})
	f.srv.WithFlowStore(ch)
	objects, err := objectstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("tag-rollup-fixture", base64.StdEncoding.EncodeToString(key))
	crypto.Zeroize(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	engine := tenantlife.New(f.db.Pool(), ch, objects, nil, nil, "test fixture has no backups", nil)
	f.srv.WithTenantLife(engine).WithFlowSnapshotStorage(FlowSnapshotStorage{
		Pool: f.db.Pool(), Objects: objects, Router: tenancy.PooledRouter{},
		Fence: tenancy.NewPostgresWriterFence(f.db.Pool()), Cache: flowsnapshot.Config{TempDir: t.TempDir()},
	})
	for _, tenant := range []string{f.a, f.b} {
		if err := tenancy.InTenant(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
			_, err := (store.TagAssignments{}).CreateManual(ctx, sc, store.ManualTagAssignmentInput{Scope: tags.Scope{TenantID: tenant, ContextID: f.contextID}, TagID: f.tagID, TargetKind: "exporter", ExporterAgentID: f.agents[tenant], ExporterSourceRef: "192.0.2.10", Value: "rollup-" + tenant})
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Truncate(time.Minute).Add(-time.Minute)
	row := flowstore.Row{TenantID: f.a, AgentID: f.agents[f.b], Exporter: "192.0.2.10", Protocol: "ipfix", TS: at, StartTS: at.Add(-time.Second), SrcAddr: "10.0.0.1", DstAddr: "10.0.0.2", SrcPort: 12345, DstPort: 443, Transport: "tcp", Sampling: 1, Bytes: 100, Packets: 1, BytesScaled: 100, PacketsScaled: 1}
	unmatched := row
	unmatched.Exporter, unmatched.SrcPort, unmatched.Bytes, unmatched.BytesScaled = "192.0.2.11", 12346, 200, 200
	foreign := row
	foreign.TenantID, foreign.AgentID, foreign.Bytes, foreign.BytesScaled = f.b, f.agents[f.a], 900, 900
	if err := ch.Insert(t.Context(), []flowstore.Row{row, unmatched, foreign}); err != nil {
		t.Fatal(err)
	}
	plan := flow.QueryPlan{From: at.Add(-time.Minute), To: at.Add(time.Minute), DataSeries: "rollup", GroupBy: []string{"tag.role"}, PageSize: 1, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	query := func(tenant string, selected flow.QueryPlan) explorerResult {
		t.Helper()
		response := apiReq(t, f.srv.Handler(), http.MethodPost, "/v1/explorer/query", tenant, ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: &selected})
		var out explorerResult
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &out) != nil || out.Flow == nil {
			t.Fatalf("actual tagged rollup snapshot: %d %s", response.Code, response.Body.String())
		}
		return out
	}
	first := query(f.a, plan)
	if first.Flow.Source != "rollup" || first.Flow.Coverage == nil || !first.Flow.Coverage.CompleteInputs || first.Flow.Totals["bytes:total"] != "300" || first.FlowPaging == nil || !first.FlowPaging.More {
		t.Fatalf("complete retained source lost real frozen page: %+v", first)
	}
	continued := query(f.a, flow.QueryPlan{Cursor: first.FlowPaging.NextCursor})
	if continued.Flow.Source != "rollup" || len(continued.Flow.Rows) != 1 || continued.Flow.Rows[0].Group["tag.role"] != "rollup-"+f.a {
		t.Fatal("actual retained continuation lost its owned tag value")
	}
	other := query(f.b, plan)
	if other.Flow.Totals["bytes:total"] != "900" || len(other.Flow.Rows) != 1 || other.Flow.Rows[0].Group["tag.role"] != "rollup-"+f.b {
		t.Fatal("same-address retained query crossed tenant tags")
	}
	path := "/v1/explorer/flow-snapshots/" + first.FlowPaging.SnapshotID + "/csv"
	if csv := apiReq(t, f.srv.Handler(), http.MethodGet, path, f.a, nil); csv.Code != http.StatusOK || !strings.Contains(csv.Body.String(), "rollup-"+f.a) || strings.Contains(csv.Body.String(), f.b) {
		t.Fatal("actual retained CSV lost or crossed tenant values")
	}
	if denied := apiReq(t, f.srv.Handler(), http.MethodGet, path, f.b, nil); denied.Code != http.StatusNotFound {
		t.Fatal("foreign tenant read retained snapshot CSV")
	}
	p := &auth.Principal{TenantID: f.a, UserID: "dev", Permissions: map[string]bool{permAIQuery: true, permFlowRead: true, permTagsRead: true}}
	backend := nativeMCPFlowBackend{f.srv}
	if _, err := backend.FlowPage(t.Context(), p, first.FlowPaging.NextCursor); err != nil {
		t.Fatalf("actual retained MCP page: %v", err)
	}
	comparison, err := backend.FlowCompare(t.Context(), p, mcp.NativeFlowCompareInput{Plan: plan, PreviousFrom: at.Add(-2 * time.Hour), PreviousTo: at.Add(-time.Hour)})
	if err != nil || comparison.Paging == nil || !comparison.Paging.More {
		t.Fatalf("actual retained comparison page: %v", err)
	}
	if _, err := backend.FlowComparisonPage(t.Context(), p, comparison.Paging.NextCursor); err != nil {
		t.Fatal("actual retained comparison could not revalidate complete source")
	}
	delete(p.Permissions, permTagsRead)
	if _, err := backend.FlowPage(t.Context(), p, first.FlowPaging.NextCursor); err == nil {
		t.Fatal("retained source bypassed current tag read grant")
	}
}
