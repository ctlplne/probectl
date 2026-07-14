// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/outage"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func outageTestResolver(ip string) (outage.Scope, bool) {
	if strings.HasPrefix(ip, "10.9.") {
		return outage.Scope{Kind: outage.ScopeASN, Code: "AS64500", Name: "Testland Telecom"}, true
	}
	return outage.Scope{}, false
}

func outageTestStore(t *testing.T) *outage.Store {
	t.Helper()
	s := outage.NewStore(0)
	s.SetEvents("ioda", []outage.Event{{
		ID: "ioda:bgp:asn:AS64500:1", Source: "ioda",
		Scope:    outage.Scope{Kind: outage.ScopeASN, Code: "AS64500", Name: "Testland Telecom"},
		Severity: "critical", Confidence: 1,
		Title: "Internet outage: Testland Telecom (AS64500)",
		Start: time.Now().Add(-30 * time.Minute),
	}})
	return s
}

func TestBuildOutageGating(t *testing.T) {
	if _, on := BuildOutage(&config.Config{OutageEnabled: false}, nil, nil, intelTestLog()); on {
		t.Fatal("disabled engine must not build")
	}
	if eng, on := BuildOutage(&config.Config{OutageEnabled: true}, nil, nil, intelTestLog()); !on || eng == nil {
		t.Fatal("enabled engine must build without feeds or enricher (degraded honestly)")
	}
	// Feeds: hard opt-in (no-phone-home).
	if _, _, on := BuildOutageFeeds(&config.Config{OutageFeedsEnabled: false}, intelTestLog()); on {
		t.Fatal("feeds must be off unless explicitly enabled")
	}
	store, refresher, on := BuildOutageFeeds(&config.Config{
		OutageFeedsEnabled: true, OutageRefresh: time.Minute, OutageRetention: time.Hour,
	}, intelTestLog())
	if !on || store == nil || refresher == nil {
		t.Fatal("enabled feeds must build")
	}
	// Without a radar token only IODA builds; health says so honestly.
	if h := refresher.Health(); len(h) != 1 || h[0].Name != "ioda" {
		t.Fatalf("want ioda only without a token, got %+v", h)
	}
}

func TestOutagesEndpointNotWired(t *testing.T) {
	srv := testServer(fakePinger{})
	rec := do(srv, http.MethodGet, "/v1/outages")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Running bool `json:"outage_running"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Running {
		t.Fatal("unwired endpoint must report outage_running=false")
	}
}

// The S47a exit criterion at the API: an external outage event correlates
// with the CALLER's affected tests — and only the caller's (guardrail 1).
func TestOutagesEndpointCorrelatesAndIsolates(t *testing.T) {
	store := outageTestStore(t)
	eng := outage.NewEngine(store, outageTestResolver)
	tid := tenancy.DefaultTenantID.String()
	now := time.Now()
	for i := 0; i < 3; i++ {
		eng.Observe(tid, "http", "web.testland.example:443", "10.9.0.1", false, now.Add(time.Duration(i)*time.Minute))
		eng.Observe("other-tenant", "http", "intruder.example:443", "10.9.0.2", false, now.Add(time.Duration(i)*time.Minute))
	}

	srv := testServer(fakePinger{}).WithOutage(eng)
	rec := do(srv, http.MethodGet, "/v1/outages")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp struct {
		Running         bool               `json:"outage_running"`
		FeedsEnabled    bool               `json:"feeds_enabled"`
		ScopeResolution bool               `json:"scope_resolution"`
		Events          []outage.EventView `json:"events"`
		Notes           []string           `json:"coverage_notes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Running || !resp.ScopeResolution {
		t.Fatalf("resp flags wrong: %+v", resp)
	}
	if resp.FeedsEnabled {
		t.Fatal("no refresher attached — feeds_enabled must be false")
	}
	if len(resp.Events) != 1 || !resp.Events[0].Ongoing {
		t.Fatalf("want the one ongoing external event, got %+v", resp.Events)
	}
	aff := resp.Events[0].Affected
	if len(aff) != 1 || aff[0].Target != "web.testland.example:443" {
		t.Fatalf("want exactly the caller's affected test, got %+v", aff)
	}
	for _, a := range aff {
		if a.Target == "intruder.example:443" {
			t.Fatal("cross-tenant affected-test leak")
		}
	}
	// The no-global-fleet honesty note always rides the payload.
	joined := strings.Join(resp.Notes, " | ")
	if !strings.Contains(joined, "global probe fleet") {
		t.Fatalf("coverage notes must state the fleet honesty, got %q", joined)
	}
	if !strings.Contains(joined, "PROBECTL_OUTAGE_FEEDS_ENABLED") {
		t.Fatalf("feeds-off note missing: %q", joined)
	}
}

// Result stream → vantage outage + external correlation; signals land as
// tenant-scoped incidents (the consumer end of the 'Done when').
func TestOutageConsumerRaisesSignals(t *testing.T) {
	store := outageTestStore(t)
	eng := outage.NewEngine(store, outageTestResolver)
	incStore := incident.NewMemoryStore()
	correlator := incident.NewCorrelator(incStore, time.Hour, intelTestLog())
	oc := NewOutageConsumer(nil, eng, correlator, intelTestLog())

	now := time.Now()
	push := func(tenant, target, peer string, ok bool, at time.Time) {
		raw, err := proto.Marshal(&resultv1.Result{
			TenantId: tenant, CanaryType: "http", ServerAddress: target,
			Success: ok, StartTimeUnixNano: at.UnixNano(),
			Attributes: map[string]string{"network.peer.address": peer},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := oc.handle(context.Background(), bus.Message{Value: raw}); err != nil {
			t.Fatal(err)
		}
	}

	// Two distinct failing targets in the event's ASN: correlation fires on
	// the first failure; vantage detection once both targets repeat-fail.
	for i := 0; i < 3; i++ {
		push("t1", "a.testland.example:443", "10.9.0.1", false, now.Add(time.Duration(i)*time.Minute))
		push("t1", "b.testland.example:443", "10.9.0.2", false, now.Add(time.Duration(i)*time.Minute))
	}
	incs, err := incStore.OpenIncidents(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) == 0 {
		t.Fatal("outage signals must open a tenant-scoped incident")
	}
	if other, _ := incStore.OpenIncidents(context.Background(), "other-tenant"); len(other) != 0 {
		t.Fatal("no other tenant may receive these incidents")
	}
	// Unscoped records are dropped (guardrail 1).
	raw, _ := proto.Marshal(&resultv1.Result{CanaryType: "http", ServerAddress: "x.example:443", Success: false})
	if err := oc.handle(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}
	// Malformed payloads are skipped, never fatal.
	if err := oc.handle(context.Background(), bus.Message{Value: []byte("garbage")}); err != nil {
		t.Fatal(err)
	}
}

func TestOutageConsumerFallsBackToServerAddress(t *testing.T) {
	eng := outage.NewEngine(nil, outageTestResolver)
	oc := NewOutageConsumer(nil, eng, nil, intelTestLog())
	// No network.peer.address attribute — peerHost(ServerAddress) is used.
	raw, _ := proto.Marshal(&resultv1.Result{
		TenantId: "t1", CanaryType: "icmp", ServerAddress: "10.9.7.7:443", Success: false,
		StartTimeUnixNano: time.Now().UnixNano(),
	})
	if err := oc.handle(context.Background(), bus.Message{Value: raw}); err != nil {
		t.Fatal(err)
	}
	snap := eng.Snapshot("t1")
	if !snap.ScopeResolution {
		t.Fatal("resolver wired — scope_resolution must be true")
	}
}
