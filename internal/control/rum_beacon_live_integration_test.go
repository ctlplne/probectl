// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

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

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/rum"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// The real-stack receipt for RUM (F20). The gap: "current tests use a fake bus and
// memory incident store; no shipping full-stack, two-tenant receipt exists."
//
// This drives the whole shipping chain — POST /ingest/rum (the PUBLIC,
// unauthenticated beacon surface) → real Kafka → the production RUMConsumer →
// engine → GET /v1/rum → `probectl rum summary` — for two tenants at once.
//
// The property that makes it worth writing rather than a fake-bus test with more
// steps: on this surface the tenant comes from the APP KEY the server registry
// resolves, never from the payload. So a beacon whose body claims another tenant's
// app must still be attributed to the key's owner. That is docs/guardrails.md G7-1
// at an ingest surface anyone on the internet can POST to, and it cannot be
// proven anywhere but end to end — the fence and the attribution live in different
// components.
func TestRUMBeaconToViewIsTenantBoundByAppKey(t *testing.T) {
	brokers := testsupport.KafkaBrokers()
	if len(brokers) == 0 {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_KAFKA not set — the RUM receipt needs a real bus")
	}
	ctx := context.Background()

	b, err := bus.NewKafka(brokers, 0, kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatalf("kafka: %v", err)
	}
	defer b.Close()

	srv, db := setupAPIServerWithLatest(t, nil)
	tenantA := freshTenant(t, db, "rumA")
	tenantB := freshTenant(t, db, "rumB")
	tenantC := freshTenant(t, db, "rumC") // no beacons

	stamp := time.Now().UnixNano()
	keyA := fmt.Sprintf("pk-a-%d", stamp)
	keyB := fmt.Sprintf("pk-b-%d", stamp)
	hostA := fmt.Sprintf("a-%d.example.test", stamp)
	hostB := fmt.Sprintf("b-%d.example.test", stamp)

	engine := rum.NewEngine()
	// The real publisher: the beacon handler puts the encoded result on the bus.
	publish := func(ctx context.Context, tenant string, payload []byte) error {
		return b.Publish(ctx, bus.RUMEventsTopic, []byte(tenant), payload)
	}
	h := srv.WithRUM(engine, map[string]RUMApp{
		keyA: {Tenant: tenantA, App: "shop-a"},
		keyB: {Tenant: tenantB, App: "shop-b"},
	}, publish, 10_000).Handler()

	// A per-run consumer group: a brand-new group starts at the earliest offset,
	// so a beacon published before the member finishes joining is still read, and
	// replayed history belongs to earlier runs' tenants rather than these.
	SetInstanceGroupSuffix(fmt.Sprintf("rum-receipt-%d", stamp))
	t.Cleanup(func() { SetInstanceGroupSuffix("") })

	// Different view counts per tenant: with equal counts a view served from the
	// wrong tenant's state is indistinguishable from a correct one.
	for i := 0; i < 2; i++ {
		liveBeacon(t, h, keyA, hostA, fmt.Sprintf("/a-%d-%d", stamp, i), http.StatusAccepted)
	}
	for i := 0; i < 4; i++ {
		liveBeacon(t, h, keyB, hostB, fmt.Sprintf("/b-%d-%d", stamp, i), http.StatusAccepted)
	}

	// The poison attempt: key A, but the body names tenant B's app and host. The
	// server must trust the key, so this becomes another tenant A view — it must
	// NOT appear under tenant B.
	poisonPage := fmt.Sprintf("/poison-%d", stamp)
	liveBeaconApp(t, h, keyA, "shop-b", hostB, poisonPage, http.StatusAccepted)

	// An unknown key is refused outright — a public surface must not accept a
	// beacon it cannot attribute.
	liveBeacon(t, h, "pk-does-not-exist", hostA, "/nope", http.StatusUnauthorized)

	// Produce BEFORE subscribing: the beacon POSTs above create the topic on a
	// fresh broker, and a brand-new group reads from the earliest offset, so the
	// consumer cannot miss them. Subscribing first is the ordering that can lose a
	// run while metadata refreshes.
	consumer := NewRUMConsumer(b, engine, nil, quietLog())
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- consumer.RunViews(runCtx) }()

	snapA := awaitRUMViews(t, h, tenantA, hostA, 2, runErr)
	snapB := awaitRUMViews(t, h, tenantB, hostB, 4, runErr)

	// The poisoned beacon landed in A (as its key says), not in B.
	if liveHostsOf(snapB) != nil && liveHasHost(snapB, hostB) {
		if views := liveViewsForHost(snapB, hostB); views != 4 {
			t.Errorf("tenant B shows %d views for its host, want 4 — the poisoned beacon was attributed by payload rather than by app key", views)
		}
	}
	if liveHasHost(snapA, hostB) {
		// A's key sent it, so A owning a view of host B is correct attribution;
		// what must never happen is B gaining it. Assert B did not.
		t.Logf("tenant A holds a view for host %s, which is correct: its own app key sent it", hostB)
	}
	if liveHasHost(snapB, hostA) {
		t.Errorf("tenant B holds a view for tenant A's host %s — cross-tenant leakage", hostA)
	}
	if got := liveRUMApps(t, h, tenantC); len(got) != 0 {
		t.Errorf("a tenant with no beacons shows %d apps", len(got))
	}

	// The operator's own path.
	live := httptest.NewServer(h)
	defer live.Close()
	out, code := runCLI(t, live.URL, tenantB, "rum", "summary")
	if code != 0 {
		t.Fatalf("`probectl rum summary` exited %d: %s", code, out)
	}
	if !strings.Contains(out, hostB) {
		t.Errorf("CLI does not show tenant B's host %s: %s", hostB, out)
	}
	if strings.Contains(out, hostA) {
		t.Errorf("CLI shows tenant A's host %s to tenant B: %s", hostA, out)
	}
}

func liveBeacon(t *testing.T, h http.Handler, key, host, page string, wantCode int) {
	t.Helper()
	liveBeaconApp(t, h, key, "", host, page, wantCode)
}

func liveBeaconApp(t *testing.T, h http.Handler, key, app, host, page string, wantCode int) {
	t.Helper()
	body, err := json.Marshal(rum.Beacon{
		V: 1, ID: fmt.Sprintf("view-%s-%d", page, time.Now().UnixNano()),
		Key: key, Consent: true, App: app, Host: host, Page: page,
		Browser: "itest", Vitals: rum.Vitals{TTFBms: 120, LCPms: 900, Loadms: 1500},
		SDK: "itest-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/ingest/rum", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != wantCode {
		t.Fatalf("POST /ingest/rum key=%s: %d %s, want %d", key, rec.Code, rec.Body, wantCode)
	}
}

func liveRUMApps(t *testing.T, h http.Handler, tenant string) []rum.AppStatus {
	t.Helper()
	rec := apiReq(t, h, http.MethodGet, "/v1/rum", tenant, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/rum as %s: %d %s", tenant, rec.Code, rec.Body)
	}
	var body struct {
		Running bool            `json:"rum_running"`
		Apps    []rum.AppStatus `json:"apps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode rum: %v", err)
	}
	if !body.Running {
		t.Fatal("the API reports RUM is not running, so the view below means nothing")
	}
	return body.Apps
}

func liveHasHost(apps []rum.AppStatus, host string) bool {
	for _, a := range apps {
		if a.Host == host {
			return true
		}
	}
	return false
}

func liveViewsForHost(apps []rum.AppStatus, host string) int {
	for _, a := range apps {
		if a.Host == host {
			return a.WindowViews
		}
	}
	return 0
}

func liveHostsOf(apps []rum.AppStatus) []string {
	out := make([]string, 0, len(apps))
	for _, a := range apps {
		out = append(out, a.Host)
	}
	return out
}

// awaitRUMViews waits for the shipping consumer to attribute wantViews page views
// for the tenant's host. A timeout says the consumer never consumed, which is a
// different failure from a wrong count and must not read the same.
func awaitRUMViews(t *testing.T, h http.Handler, tenant, host string, wantViews int, runErr <-chan error) []rum.AppStatus {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	var last []rum.AppStatus
	for time.Now().Before(deadline) {
		select {
		case err := <-runErr:
			t.Fatalf("the RUM consumer stopped before attributing anything: %v", err)
		default:
		}
		last = liveRUMApps(t, h, tenant)
		if liveViewsForHost(last, host) >= wantViews {
			return last
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("tenant %s shows %d views for %s after 45s, want %d (hosts seen: %v) — the shipping consumer did not attribute the published beacons",
		tenant, liveViewsForHost(last, host), host, wantViews, liveHostsOf(last))
	return last
}
