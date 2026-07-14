// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package endpoint

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/store/endpointstore"
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
