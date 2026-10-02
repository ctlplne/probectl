// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
)

// TestEndpointConsumersFailClosedWithoutBinding is the INV-08 regression. The
// endpoint/DEM agent asserts its tenant from local YAML with no certificate, so
// its lane is a VERIFYING lane whose shared (pooled) leg, consumed with a nil
// binding, would treat the payload's claimed tenant as authoritative. Both the
// in-RAM view consumer and the durable event consumer must therefore REFUSE TO
// START without a registry binding — the invariant, not merely a production
// wiring convention. Pre-fix both consumers subscribed and silently accepted
// whatever tenant a laptop claimed.
func TestEndpointConsumersFailClosedWithoutBinding(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	repo := endpoint.NewRepository(endpointstore.NewMemory(), endpoint.NewSnapshotStore(0))

	cases := []struct {
		name string
		run  func(ctx context.Context) error
	}{
		{"view", func(ctx context.Context) error {
			return NewEndpointViewConsumer(bus.NewMemory(), endpoint.NewSnapshotStore(0), log).Run(ctx)
		}},
		{"events", func(ctx context.Context) error {
			return NewEndpointEventConsumer(bus.NewMemory(), repo, log).Run(ctx)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A short deadline so that, PRE-FIX (no guard), Run falls through to
			// RunLanes and blocks on Subscribe until the deadline — returning nil
			// or a context error, never a binding error. POST-FIX the guard
			// returns the binding error immediately, before any subscription.
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			err := tc.run(ctx)
			if err == nil || !strings.Contains(err.Error(), "binding") {
				t.Fatalf("INV-08: %s consumer must fail closed without a tenant binding; got err=%v", tc.name, err)
			}
		})
	}
}

// TestEndpointViewConsumerRejectsForgedTenantAtIngest closes the gap the
// durable leg already covered but the in-RAM view leg did not: a payload whose
// (tenant, agent) pair is not enrolled must never reach the snapshot store that
// backs GET /v1/endpoints. Agent A is registered only to tenant A; a payload
// claiming tenant B is rejected at ingest, not merely filtered at read time.
func TestEndpointViewConsumerRejectsForgedTenantAtIngest(t *testing.T) {
	ctx := context.Background()
	store := endpoint.NewSnapshotStore(0)
	consumer := NewEndpointViewConsumer(bus.NewMemory(), store, slog.New(slog.NewTextHandler(io.Discard, nil))).
		WithTenantBinding(endpointTestBinding{{"tenant-a", "agent-a"}: true})

	message := func(tenant string) bus.Message {
		value, err := proto.Marshal(&resultv1.Result{
			TenantId: tenant, AgentId: "agent-a", CanaryType: endpoint.TypeWiFi,
			ServerAddress: tenant + "-ssid", Success: true, StartTimeUnixNano: time.Now().UnixNano(),
		})
		if err != nil {
			t.Fatal(err)
		}
		return bus.Message{Topic: bus.EndpointResultsTopic, Key: []byte(tenant), Value: value}
	}

	if err := consumer.handleLane(ctx, message("tenant-b"), ""); err != nil {
		t.Fatal(err)
	}
	if got := store.List("tenant-b"); len(got) != 0 {
		t.Fatalf("INV-08: forged tenant reached the view store: %+v", got)
	}
	if err := consumer.handleLane(ctx, message("tenant-a"), ""); err != nil {
		t.Fatal(err)
	}
	if got := store.List("tenant-a"); len(got) != 1 {
		t.Fatalf("INV-08: authoritative tenant view rows = %+v", got)
	}
}
