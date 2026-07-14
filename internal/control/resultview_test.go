// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestLatestResultsStore(t *testing.T) {
	s := NewLatestResults(3)
	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

	s.Record("t-a", ResultView{Type: "http", Target: "https://app.acme.example", AgentID: "a1",
		Metrics: map[string]float64{"http.total.ms": 500}, ObservedAt: at})
	// Newer result for the same series wins; older never regresses.
	s.Record("t-a", ResultView{Type: "http", Target: "https://app.acme.example", AgentID: "a1",
		Metrics: map[string]float64{"http.total.ms": 320}, ObservedAt: at.Add(time.Minute)})
	s.Record("t-a", ResultView{Type: "http", Target: "https://app.acme.example", AgentID: "a1",
		Metrics: map[string]float64{"http.total.ms": 999}, ObservedAt: at.Add(-time.Hour)})
	s.Record("t-b", ResultView{Type: "icmp", Target: "10.9.9.9", AgentID: "b1", ObservedAt: at})
	s.Record("", ResultView{Type: "icmp", Target: "x", ObservedAt: at}) // unscoped: dropped
	s.Record("t-a", ResultView{Target: "x", ObservedAt: at})            // type-less: dropped

	got := s.List("t-a")
	if len(got) != 1 || got[0].Metrics["http.total.ms"] != 320 {
		t.Fatalf("latest = %+v", got)
	}
	for _, v := range got {
		if v.Target == "10.9.9.9" {
			t.Fatal("CROSS-TENANT LEAK in List")
		}
	}

	// Cap eviction drops the stalest series.
	for i := 0; i < 4; i++ {
		s.Record("t-a", ResultView{Type: "icmp", Target: fmt.Sprintf("10.0.0.%d", i), AgentID: "a1",
			ObservedAt: at.Add(time.Duration(i+2) * time.Minute)})
	}
	if s.Len("t-a") != 3 {
		t.Fatalf("len = %d, want cap 3", s.Len("t-a"))
	}
}

// TestLatestResultsEndToEnd: published results land in the store and serve
// through /v1/results/latest, tenant-scoped, full metrics + attributes intact.
func TestLatestResultsEndToEnd(t *testing.T) {
	b := bus.NewMemory()
	store := NewLatestResults(0)
	consumer := NewResultViewConsumer(b, store, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = consumer.Run(ctx) }()
	time.Sleep(20 * time.Millisecond)

	at := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	def := tenancy.DefaultTenantID.String()
	publish := func(r *resultv1.Result) {
		value, err := proto.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.Publish(ctx, bus.NetworkResultsTopic, []byte(r.GetTenantId()), value); err != nil {
			t.Fatal(err)
		}
	}
	publish(&resultv1.Result{
		TenantId: def, AgentId: "a1", CanaryType: "dns", ServerAddress: "acme.example",
		Success: true, StartTimeUnixNano: at.UnixNano(),
		Metrics:    map[string]float64{"dns.query.ms": 12.5, "dns.answers": 2, "dns.dnssec.secure": 1},
		Attributes: map[string]string{"dns.rcode": "NOERROR", "dns.answer": "203.0.113.10, 203.0.113.11"},
	})
	publish(&resultv1.Result{
		TenantId: "00000000-0000-0000-0000-000000000002", AgentId: "evil", CanaryType: "icmp",
		ServerAddress: "secret.example", Success: true, StartTimeUnixNano: at.UnixNano(),
	})
	_ = b.Publish(ctx, bus.NetworkResultsTopic, []byte(def), []byte("garbage"))

	srv := testServer(fakePinger{}).WithLatestResults(store)
	deadline := time.Now().Add(2 * time.Second)
	for {
		rec := do(srv, http.MethodGet, "/v1/results/latest")
		var resp struct {
			CollectorRunning bool         `json:"collector_running"`
			Items            []ResultView `json:"items"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Items) == 1 {
			v := resp.Items[0]
			if !resp.CollectorRunning || v.Type != "dns" || v.Metrics["dns.query.ms"] != 12.5 ||
				v.Attributes["dns.rcode"] != "NOERROR" {
				t.Fatalf("view = %+v", v)
			}
			if strings.Contains(rec.Body.String(), "secret.example") {
				t.Fatalf("CROSS-TENANT LEAK: %s", rec.Body.String())
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("result never landed: %s", rec.Body.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The other tenant sees only its own result.
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/results/latest", nil)
	req.Header.Set("X-Probectl-Tenant", "00000000-0000-0000-0000-000000000002")
	srv.Handler().ServeHTTP(rec2, req)
	if !strings.Contains(rec2.Body.String(), "secret.example") || strings.Contains(rec2.Body.String(), "acme.example") {
		t.Fatalf("other-tenant view wrong: %s", rec2.Body.String())
	}

	// No store wired: honest empty response.
	bare := do(testServer(fakePinger{}), http.MethodGet, "/v1/results/latest")
	if bare.Code != http.StatusOK || !strings.Contains(bare.Body.String(), `"collector_running":false`) {
		t.Fatalf("bare = %d %s", bare.Code, bare.Body.String())
	}
}

func TestLatestResultsRoutePerm(t *testing.T) {
	for _, rt := range testServer(fakePinger{}).apiRoutes() {
		if rt.Pattern == "/v1/results/latest" {
			if rt.Permission != permTestRead {
				t.Fatalf("perm = %q, want test.read", rt.Permission)
			}
			return
		}
	}
	t.Fatal("/v1/results/latest not registered")
}
