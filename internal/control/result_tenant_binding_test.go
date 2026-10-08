// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/rum"
)

func TestBindResultTenant(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload string
		key     []byte
		lane    string
		want    string // "" = refused
	}{
		{"namespaced lane wins over a disagreeing payload", "tenant-b", bus.TenantKey("tenant-b", "agent-1"), "tenant-a", "tenant-a"},
		{"shared lane, key and payload agree", "tenant-a", bus.TenantKey("tenant-a", "agent-1"), "", "tenant-a"},
		{"shared lane, unbucketed key agrees", "tenant-a", []byte("tenant-a"), "", "tenant-a"},
		{"shared lane, payload claims another tenant", "tenant-b", bus.TenantKey("tenant-a", "agent-1"), "", ""},
		{"shared lane, no key", "tenant-a", nil, "", ""},
		{"shared lane, empty payload tenant", "", bus.TenantKey("tenant-a", "agent-1"), "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &resultv1.Result{TenantId: tc.payload}
			ok := bindResultTenant(r, bus.Message{Key: tc.key}, tc.lane)
			if tc.want == "" {
				if ok {
					t.Fatalf("bound a record the key does not vouch for (payload %q, key %q)", tc.payload, tc.key)
				}
				return
			}
			if !ok || r.GetTenantId() != tc.want {
				t.Fatalf("bound = %v tenant %q, want true %q", ok, r.GetTenantId(), tc.want)
			}
		})
	}
}

// TestSharedLaneResultConsumersRefuseAForgedTenant (ING-03, G7-1): on the
// shared result and RUM lanes any bus-credential holder can publish, so a
// record keyed to tenant A whose payload claims tenant B must reach none of
// B's state. The storage pipeline and the OTLP export consumer already refused
// it; the result fan (latest-results view, IOC, NDR, TLS posture, outage and
// RUM synthetic sinks), the SLO consumer and the RUM event consumer trusted the
// payload, so the forged record landed in B's views and signals.
func TestSharedLaneResultConsumersRefuseAForgedTenant(t *testing.T) {
	ctx := context.Background()
	forgedKey := bus.TenantKey("tenant-a", "agent-1")
	marshal := func(r *resultv1.Result) []byte {
		t.Helper()
		raw, err := proto.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	t.Run("result fan", func(t *testing.T) {
		latest := NewLatestResults(0)
		fan := NewResultFan(nil, intelTestLog(), ResultSink{Name: "result-view", Fn: NewResultViewConsumer(nil, latest, intelTestLog()).SinkResult})
		forged := marshal(&resultv1.Result{TenantId: "tenant-b", AgentId: "agent-1", CanaryType: "http", ServerAddress: "forged.example", Success: true})
		if err := fan.handleLane(ctx, bus.Message{Key: forgedKey, Value: forged}, ""); err != nil {
			t.Fatal(err)
		}
		if got := latest.List("tenant-b"); len(got) != 0 {
			t.Fatalf("a record keyed to tenant-a reached tenant-b's latest results: %+v", got)
		}
		legit := marshal(&resultv1.Result{TenantId: "tenant-b", AgentId: "agent-1", CanaryType: "http", ServerAddress: "real.example", Success: true})
		if err := fan.handleLane(ctx, bus.Message{Key: bus.TenantKey("tenant-b", "agent-1"), Value: legit}, ""); err != nil {
			t.Fatal(err)
		}
		if got := latest.List("tenant-b"); len(got) != 1 {
			t.Fatalf("tenant-b's own keyed result = %d views, want 1", len(got))
		}
		if fan.rejected.Load() != 1 {
			t.Fatalf("fan rejected %d records, want 1", fan.rejected.Load())
		}
	})

	t.Run("slo consumer", func(t *testing.T) {
		eng := sloTestEngine(t)
		sc := NewSLOConsumer(nil, eng, incident.NewCorrelator(incident.NewMemoryStore(), time.Hour, intelTestLog()), intelTestLog())
		forged := marshal(&resultv1.Result{TenantId: "tenant-b", CanaryType: "http", ServerAddress: "web.acme.example",
			Success: false, StartTimeUnixNano: time.Now().UnixNano()})
		if err := sc.handleLane(ctx, bus.Message{Key: forgedKey, Value: forged}, ""); err != nil {
			t.Fatal(err)
		}
		for _, st := range eng.Statuses("tenant-b") {
			if st.TotalEvents != 0 {
				t.Fatalf("a record keyed to tenant-a burned tenant-b's SLO %s (%d events)", st.Name, st.TotalEvents)
			}
		}
	})

	t.Run("rum event consumer", func(t *testing.T) {
		eng := rum.NewEngine()
		rc := NewRUMConsumer(nil, eng, nil, intelTestLog())
		forged := marshal(&resultv1.Result{TenantId: "tenant-b", CanaryType: "rum", ServerAddress: "web.acme.example", Success: false,
			StartTimeUnixNano: time.Now().UnixNano()})
		if err := rc.handleRUMEventLane(ctx, bus.Message{Key: []byte("tenant-a"), Value: forged}, ""); err != nil {
			t.Fatal(err)
		}
		if apps := eng.Snapshot("tenant-b").Apps; len(apps) != 0 {
			t.Fatalf("a RUM event keyed to tenant-a reached tenant-b: %+v", apps)
		}
	})
}
