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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/ai"
	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/flow"
	flowv1 "github.com/ctlplne/probectl/internal/gen/probectl/flow/v1"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/tenantlife"
)

func TestKubernetesFlowExplorerPublishesOnlyCurrentOwnedIntervals(t *testing.T) {
	f, rows, _, began := newRoleFlowQueryFixture(t)
	f.server.WithFlowStore(rows.Memory)
	objects, err := objectstore.NewFS(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.Random(32)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := tenantcrypto.NewEnvelopeSealer("kubernetes-flow-fixture", base64.StdEncoding.EncodeToString(key))
	crypto.Zeroize(key)
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)
	engine := tenantlife.New(f.pool, rows.Memory, objects, nil, nil, "fixture has no backups", nil)
	f.server.WithTenantLife(engine).WithFlowSnapshotStorage(FlowSnapshotStorage{
		Pool: f.pool, Objects: objects, Router: tenancy.PooledRouter{},
		Fence: tenancy.NewPostgresWriterFence(f.pool), Cache: flowsnapshot.Config{TempDir: t.TempDir()},
	})

	cluster := uuid(t)
	sources := make([]store.KubernetesInventorySource, len(f.tenants))
	var latest time.Time
	for lane, tenant := range f.tenants {
		agent := uuid(t)
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := (store.Agents{}).Reserve(ctx, sc, agent, "inventory", "fixture", "", crypto.AgentSPIFFEID(tenant, agent), nil); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_agent_contexts(tenant_id,agent_id,context_id) VALUES($1,$2,$3)`,
				tenant, agent, f.contextID); err != nil {
				return err
			}
			tolerance := int64(2)
			var err error
			sources[lane], err = store.CreateKubernetesInventorySourceInScope(ctx, sc, f.contextID,
				store.KubernetesInventorySourceInput{ClusterID: cluster, Namespace: "inventory", AgentID: agent, FlowClockErrorMS: &tolerance})
			return err
		})
		from, until := seedKubernetesTopologyFixture(t, f, tenant, sources[lane], lane)
		if until.After(latest) {
			latest = until
		}
		for sample, window := range [][2]time.Time{{from.Add(8 * time.Millisecond), from.Add(10 * time.Millisecond)},
			{until.Add(-time.Millisecond), until}} {
			flowRow := captureKubernetesTestFlow(t, f, tenant, window[0], window[1], sample)
			if err := rows.Insert(t.Context(), []flowstore.Row{flowRow}); err != nil {
				t.Fatal(err)
			}
		}
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	plan := flow.QueryPlan{From: began.Add(-time.Second), To: latest.Add(time.Second), View: "table", PageSize: 1,
		GroupBy: []string{"src_k8s_pod"}, Metrics: []flow.QueryMetric{{Measure: "bytes", Calculation: "total", Role: "primary"}}}
	request := func(tenant, method, path string, plan *flow.QueryPlan) (int, []byte) {
		t.Helper()
		var body bytes.Buffer
		if plan != nil {
			if err := json.NewEncoder(&body).Encode(ai.ExplorerQuery{Source: ai.ExplorerFlow, Flow: plan}); err != nil {
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
		payload, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, payload
	}
	first := make([]explorerResult, len(f.tenants))
	seedInterfaceRoleMCPConsent(f)
	native := interfaceRoleNativeTLSCaller(t, f, "2026-07-28")
	const queryPath = "/v1/explorer/query"
	for lane, tenant := range f.tenants {
		status, raw := request(tenant, http.MethodPost, queryPath, &plan)
		var page explorerResult
		if status != http.StatusOK || json.Unmarshal(raw, &page) != nil || page.Flow == nil ||
			page.FlowPaging == nil || !page.FlowPaging.More || page.FlowPaging.SnapshotID == "" {
			t.Fatalf("tenant %d could not freeze Kubernetes attribution: HTTP %d %.800s", lane, status, raw)
		}
		first[lane] = page
		csvPath := "/v1/explorer/flow-snapshots/" + page.FlowPaging.SnapshotID + "/csv"
		status, raw = request(tenant, http.MethodGet, csvPath, nil)
		records, err := csv.NewReader(bytes.NewReader(raw)).ReadAll()
		if status != http.StatusOK || err != nil || len(records) != 4 || len(records[0]) != 3 ||
			records[0][1] != "src_k8s_pod" || records[2][1] != fmt.Sprintf("pod-%d", lane) || records[2][2] != "7" ||
			len(page.Flow.Rows) != 1 || page.Flow.Rows[0].Group["src_k8s_pod"] != "" {
			t.Fatalf("tenant %d lost the proven Pod or mislabeled crossing flows: HTTP %d %.800s", lane, status, raw)
		}
		var nativePage mcp.NativeFlowQueryResult
		native(tenant, "flow_explorer_page", map[string]any{"cursor": page.FlowPaging.NextCursor}, &nativePage, true)
		if len(nativePage.Flow.Rows) != 1 || len(nativePage.Flow.Rows[0].Group) != 1 ||
			nativePage.Flow.Rows[0].Group[0].Field != "src_k8s_pod" ||
			nativePage.Flow.Rows[0].Group[0].Value != fmt.Sprintf("pod-%d", lane) {
			t.Fatalf("tenant %d native page lost its proven Pod", lane)
		}
	}
	a, b := f.tenants[0], f.tenants[1]
	for lane, tenant := range f.tenants {
		foreign := flow.QueryPlan{Cursor: first[1-lane].FlowPaging.NextCursor}
		if status, _ := request(tenant, http.MethodPost, queryPath, &foreign); status < http.StatusBadRequest {
			t.Fatalf("tenant %d resumed a sibling result", lane)
		}
	}
	f.in(a, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := store.RevokeKubernetesInventorySourceInScope(ctx, sc, f.contextID, sources[0].ID)
		return err
	})
	for lane, tenant := range []string{a, b} {
		cursor := flow.QueryPlan{Cursor: first[lane].FlowPaging.NextCursor}
		status, raw := request(tenant, http.MethodPost, queryPath, &cursor)
		if lane == 0 && status < http.StatusBadRequest || lane == 1 &&
			(status != http.StatusOK || !bytes.Contains(raw, []byte("pod-1"))) {
			t.Fatalf("revocation did not respect tenant %d's frozen result: HTTP %d %.700s", lane, status, raw)
		}
	}
	prune := store.NewKubernetesInventoryPruner(f.pool)
	cutoff := time.Now().UTC()
	if deleted, err := prune(tenancy.WithTenant(t.Context(), tenancy.ID(b)), a, cutoff); err == nil || deleted != 0 {
		t.Fatal("inventory retention accepted a contradictory tenant scope", deleted, err)
	}
	if deleted, err := prune(t.Context(), a, cutoff); err != nil || deleted != 1 {
		t.Fatal("inventory retention did not remove the exact old generation", deleted, err)
	}
	peer := flow.QueryPlan{Cursor: first[1].FlowPaging.NextCursor}
	if status, body := request(b, http.MethodPost, queryPath, &peer); status != http.StatusOK || !bytes.Contains(body, []byte("pod-1")) {
		t.Fatalf("inventory retention crossed the sibling's retained result: HTTP %d %.700s", status, body)
	}
}

func captureKubernetesTestFlow(t *testing.T, f *roleExplanationAPIFixture, tenant string, from, until time.Time, sample int) flowstore.Row {
	t.Helper()
	input := entity.FlowCaptureInput{Exporter: netip.MustParseAddr("192.0.2.1"),
		Source: netip.MustParseAddr("10.244.0.15"), Destination: netip.MustParseAddr("198.51.100.1"),
		Protocol: "ipfix", Domain: 4294967295}
	var digest [32]byte
	copy(digest[:], crypto.Hash(fmt.Appendf(nil, "inventory-flow-%d", sample)))
	ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
	ref, err := store.NewBGPRoutingFlowCaptures(f.pool).CaptureAuthenticated(ctx, "role-flow", digest, input,
		store.BGPRoutingBudget{MemoryBytes: 16 << 20, WorkUnits: 32 << 20, StateBytes: 16 << 20})
	if err != nil || ref.CapturedAt.IsZero() {
		t.Fatal("original flow capture is unavailable", ref, err)
	}
	return flowstore.Row{TenantID: tenant, AgentID: "role-flow", TS: until, StartTS: from,
		Exporter: input.Exporter.String(), SrcAddr: input.Source.String(), DstAddr: input.Destination.String(),
		Protocol: input.Protocol, ObsDomain: input.Domain, BytesScaled: 7,
		ClockBasis: flowv1.FlowClockBasis_FLOW_CLOCK_BASIS_EXPORTER_INTERVAL, RawFlowDigest: hex.EncodeToString(digest[:]),
		RoutingCaptureKey: hex.EncodeToString(ref.Key[:]), RoutingCapturedUnixNanos: ref.CapturedAt.UnixNano()}
}
