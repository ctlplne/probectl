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
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/change"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/internal/testsupport/chtest"
)

func TestPathChangeTimelineKeepsTwoTenantsAndOriginalRounds(t *testing.T) {
	endpoint := os.Getenv("PROBECTL_TEST_CLICKHOUSE_URL")
	if endpoint == "" {
		testsupport.SkipOrFatal(t, "the scoped path change check requires ClickHouse")
	}
	f := newRoleExplanationAPIFixture(t, slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelWarn})))
	backend, err := pathstore.NewClickHouseRetainedWithClient(endpoint, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, readerClient := chtest.ProvisionReader(t, endpoint, "path_change_reader")
	backend.WithTenantScoping(true).WithReader(readerClient)
	if err := backend.EnsureReaderRowPolicy(t.Context(), reader); err != nil {
		t.Fatal(err)
	}
	if err := backend.VerifyReaderIsolation(t.Context(), reader); err != nil {
		t.Fatal(err)
	}
	batch := pathstore.NewBatchingSaver(backend, f.server.log, 100*time.Millisecond, 32)
	t.Cleanup(func() { _ = batch.Close() })
	f.server.pathStore = batch
	enricher := opendata.NewEnricher(f.server.log)
	index := opendata.NewASNFile()
	if err := index.Load(strings.NewReader("192.0.2.0/24,64496,Before\n198.51.100.0/24,64497,After\n")); err != nil {
		t.Fatal(err)
	}
	enricher.Register(index)
	f.server.WithOpenDataStatus(enricher, nil, nil)
	notify := make(chan string, 8)
	f.server.WithPathChangeObserver(func(_ context.Context, in *incident.Incident, opened bool) {
		if opened {
			notify <- in.TenantID
		}
	})
	var changed atomic.Bool
	f.server.discover = func(ctx context.Context, cfg path.Config) (*path.Path, error) {
		bound, _ := tenancy.FromContext(ctx)
		middle := "192.0.2.2"
		if bound.String() == f.tenants[0] && changed.Load() {
			middle = "198.51.100.2"
		}
		p := samplePath(cfg.Target)
		p.Hops = []path.Hop{
			{TTL: 2, Nodes: []path.HopNode{{IP: "192.0.2.1", Received: 3, RTTMinMs: 1, RTTMaxMs: 2, QuotedTTL: 2}}},
			{TTL: 3, Nodes: []path.HopNode{{IP: middle, Received: 3, RTTMinMs: 4, RTTMaxMs: 5, QuotedTTL: 3}}},
			{TTL: 4, Nodes: []path.HopNode{{IP: cfg.Target, Received: 3, RTTMinMs: 7, RTTMaxMs: 8}}},
		}
		p.Links = []path.Link{{TTL: 2, From: p.Hops[0].Nodes[0].IP, To: middle}, {TTL: 3, From: middle, To: cfg.Target}}
		return p, nil
	}
	socket := httptest.NewTLSServer(f.server.Handler())
	t.Cleanup(socket.Close)
	const target = "9.9.9.9"
	var tests [2]string
	for lane, tenant := range f.tenants {
		f.in(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, permission := range []string{permTestRead, permTestWrite, permChangeRead, permIncidentRead, permAIQuery} {
				if err := (store.Roles{}).AddPermission(ctx, sc, f.roles[tenant], permission); err != nil {
					return err
				}
			}
			owned, err := (store.Tests{}).Create(ctx, sc, store.TestInput{Name: "same test", Type: "icmp", Target: target,
				IntervalSeconds: 60, TimeoutSeconds: 3, Enabled: true})
			if err == nil {
				tests[lane] = owned.ID
			}
			return err
		})
	}
	for step := range 4 {
		changed.Store(step > 0)
		for lane, tenant := range f.tenants {
			callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodPost, "/v1/tests/"+tests[lane]+"/path", nil, http.StatusOK)
		}
		if step < 2 && len(notify) != 0 {
			t.Fatal("path change delivered before the second confirming round")
		}
	}
	if len(notify) != 1 || <-notify != f.tenants[0] {
		t.Fatal("expected one notification for the changed tenant")
	}
	for lane, tenant := range f.tenants {
		raw := callSeasonalAPI(t, socket, f.tokens[tenant], http.MethodGet, "/v1/changes", nil, http.StatusOK)
		var view struct{ Items []change.Event }
		if err := json.Unmarshal(raw, &view); err != nil || len(view.Items) != 1-lane || bytes.Contains(raw, []byte(tests[1-lane])) {
			t.Fatalf("tenant %d received the wrong change timeline: %s", lane, raw)
		}
		if lane == 1 {
			continue
		}
		event := view.Items[0]
		if event.Source != pathChangeSource || event.Ref != tests[lane] || event.Attributes["changed_hops"] != "1" || event.Attributes["changed_origins"] != "1" {
			t.Fatalf("timeline did not preserve confirmed hop and ASN changes: %+v", event)
		}
		id := event.Attributes["confirmed_round_id"]
		seedInterfaceRoleMCPConsent(f)
		for _, revision := range []string{"2026-07-28", "2025-11-25"} {
			call := interfaceRoleNativeTLSCaller(t, f, revision)
			var timeline struct{ Items []change.Event }
			call(tenant, "changes_list", map[string]any{"limit": 1}, &timeline, true)
			if len(timeline.Items) != 1 || timeline.Items[0].Ref != tests[lane] || timeline.Items[0].Attributes["confirmed_round_id"] != id {
				t.Fatal("native timeline lost the owned path citation", revision)
			}
			var original struct{ Items []pathstore.Snapshot }
			call(tenant, "path_history", map[string]any{"test_id": tests[lane], "round_id": []string{id}}, &original, true)
			if len(original.Items) != 1 || original.Items[0].ID != id || len(original.Items[0].Path.InferredMPLS) != 1 {
				t.Fatal("native path history lost its round and inference", revision)
			}
			call(f.tenants[1], "path_history", map[string]any{"test_id": tests[lane], "round_id": []string{id}}, nil, false)
		}
		for peer := range f.tenants {
			query := "/v1/tests/" + tests[peer] + "/path/history?round_id=" + id
			raw := callSeasonalAPI(t, socket, f.tokens[f.tenants[peer]], http.MethodGet, query, nil, http.StatusOK)
			var history struct{ Items []pathstore.Snapshot }
			if err := json.Unmarshal(raw, &history); err != nil || len(history.Items) != 1-peer {
				t.Fatalf("retained round escaped its tenant scope: %s", raw)
			}
			if peer == 0 && (history.Items[0].ID != id || len(history.Items[0].Path.InferredMPLS) != 1) {
				t.Fatalf("retained round lost its quoted TTL inference: %s", raw)
			}
		}
	}
}
