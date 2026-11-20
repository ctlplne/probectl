// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package endpoint

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store/endpointstore"
)

func TestEndpointDurableRestartAndIsolation(t *testing.T) {
	ctx := context.Background()
	durable := endpointstore.NewMemory()
	at := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)

	firstProcess := NewRepository(durable, NewSnapshotStore(0))
	for _, record := range []struct {
		tenant, agent string
		view          ResultView
	}{
		{"tenant-a", "laptop-a", ResultView{Type: TypeAttribution, Target: "app-a", Success: false, Metrics: map[string]float64{"slow": 1}, Attributes: map[string]string{"endpoint.cause": "wifi"}, ObservedAt: at}},
		{"tenant-a", "laptop-a", ResultView{Type: TypeWiFi, Target: "A-SSID", Success: true, Attributes: map[string]string{"wifi.ssid": "A-SSID"}, ObservedAt: at}},
		{"tenant-b", "decoy-b", ResultView{Type: TypeWiFi, Target: "SECRET-B", Success: true, Attributes: map[string]string{"wifi.ssid": "SECRET-B"}, ObservedAt: at}},
	} {
		if err := firstProcess.Persist(ctx, record.tenant, record.agent, record.view); err != nil {
			t.Fatal(err)
		}
	}

	// A brand-new repository/cache represents a control-plane restart. Only the
	// durable store survives; the first tenant read must rebuild the snapshot.
	afterRestart := NewRepository(durable, NewSnapshotStore(0))
	itemsA, err := afterRestart.ListFilteredContext(ctx, "tenant-a", ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(itemsA) != 1 || itemsA[0].AgentID != "laptop-a" || itemsA[0].WiFi == nil {
		t.Fatalf("restart-restored tenant A = %+v", itemsA)
	}
	if strings.Contains(itemsA[0].WiFi.Target, "SECRET-B") {
		t.Fatalf("cross-tenant decoy leaked into tenant A: %+v", itemsA)
	}
	itemsB, err := afterRestart.ListFilteredContext(ctx, "tenant-b", ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(itemsB) != 1 || itemsB[0].AgentID != "decoy-b" || itemsB[0].WiFi.Target != "SECRET-B" {
		t.Fatalf("tenant B partition = %+v", itemsB)
	}
	if _, err := durable.Latest(ctx, ""); err == nil {
		t.Fatal("unscoped durable query must fail closed")
	}
}

func TestEndpointReplayRefreshesEachTenantAfterFirstRestartRead(t *testing.T) {
	ctx := t.Context()
	durable := endpointstore.NewMemory()
	repository := NewRepository(durable, NewSnapshotStore(0))
	at := time.Date(2026, 11, 20, 9, 24, 29, 0, time.UTC)
	const agent = "same-endpoint-id"
	tenants := []string{"tenant-a", "tenant-b"}
	for _, tenant := range tenants {
		if err := repository.Persist(ctx, tenant, agent, ResultView{Type: TypeAttribution, Success: true, ObservedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	restarted := NewRepository(durable, NewSnapshotStore(0))
	for _, tenant := range tenants {
		items, err := restarted.ListFilteredContext(ctx, tenant, ListFilter{})
		if err != nil || len(items) != 1 || items[0].AgentID != agent || len(items[0].Sessions) != 0 {
			t.Fatal("first read did not establish the attribution-only snapshot", tenant, items, err)
		}
	}
	for _, tenant := range tenants {
		view := ResultView{Type: TypeSession, Target: "https://" + tenant + ".example.test/readyz", Success: true,
			ObservedAt: at.Add(time.Second), Metrics: map[string]float64{"status": 200}}
		if err := restarted.Persist(ctx, tenant, agent, view); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range tenants {
		items, err := restarted.ListFilteredContext(ctx, tenant, ListFilter{})
		if err != nil || len(items) != 1 || len(items[0].Sessions) != 1 || items[0].Sessions[0].Target != "https://"+tenant+".example.test/readyz" {
			t.Fatal("late durable replay did not restore exactly the owned session", tenant, items, err)
		}
	}
}
