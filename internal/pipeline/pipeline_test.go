// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package pipeline

import (
	"context"
	"io"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

func TestResultToSeries(t *testing.T) {
	r := &resultv1.Result{
		TenantId:          "t1",
		AgentId:           "a1",
		CanaryType:        "icmp",
		ServerAddress:     "host.example",
		Success:           true,
		DurationNano:      5_000_000, // 5ms
		StartTimeUnixNano: 1_700_000_000_000_000_000,
		Metrics:           map[string]float64{"rtt.avg.ms": 12.5},
	}
	byName := map[string]tsdb.Series{}
	for _, s := range ResultToSeries(r) {
		byName[s.Metric] = s
	}
	if byName["probectl_probe_success"].Value != 1 {
		t.Errorf("success = %v, want 1", byName["probectl_probe_success"].Value)
	}
	if d := byName["probectl_probe_duration_seconds"].Value; d < 0.0049 || d > 0.0051 {
		t.Errorf("duration_seconds = %v, want ~0.005", d)
	}
	if _, ok := byName["probectl_probe_rtt_avg_ms"]; !ok {
		t.Error("missing custom metric probectl_probe_rtt_avg_ms (dot sanitization)")
	}
	lbl := byName["probectl_probe_success"].Labels
	if lbl["tenant_id"] != "t1" || lbl["agent_id"] != "a1" || lbl["canary_type"] != "icmp" || lbl["server_address"] != "host.example" {
		t.Errorf("labels = %v", lbl)
	}
}

// DPR-066: a result stamped with the server test id carries it as a series
// label, so two definitions against the same host never share a series.
func TestResultToSeriesCarriesTestID(t *testing.T) {
	r := &resultv1.Result{TenantId: "t1", AgentId: "a1", CanaryType: "http", ServerAddress: "example.com", Success: true,
		Attributes: map[string]string{"probectl.test.id": "98bbc817-d2f0-403b-b067-fae2ca28de1e"}}
	for _, s := range ResultToSeries(r) {
		if s.Labels["test_id"] != "98bbc817-d2f0-403b-b067-fae2ca28de1e" || s.Labels["server_address"] != "example.com" {
			t.Fatalf("labels = %v", s.Labels)
		}
	}
	plain := ResultToSeries(&resultv1.Result{TenantId: "t1", AgentId: "a1", CanaryType: "http", ServerAddress: "example.com"})
	if _, ok := plain[0].Labels["test_id"]; ok {
		t.Fatal("an unstamped result must not mint an empty test_id label")
	}
}

// TestConsumerWritesToTSDB proves the S6 Done-when at the unit level: a result
// published to the bus is converted and becomes queryable in the TSDB.
func TestConsumerWritesToTSDB(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := bus.NewMemory()
	defer b.Close()
	w := tsdb.NewMemory()
	c := NewConsumer(b, w, "test", logging.New(io.Discard, "error", "json")).WithTenantBinding(allowAllBinding{})

	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	// TEST-002: synchronize on the subscription instead of a fixed sleep — a
	// live pub/sub bus only delivers to subscribers present at publish time.
	if !b.WaitForSubscribers(ctx, bus.NetworkResultsTopic, 1) {
		t.Fatal("consumer did not subscribe to the network results topic")
	}

	payload, err := proto.Marshal(&resultv1.Result{TenantId: "t1", AgentId: "a1", CanaryType: "noop", Success: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(ctx, bus.NetworkResultsTopic, []byte("t1"), payload); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(w.Query("probectl_probe_success", map[string]string{"tenant_id": "t1"})) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	got := w.Query("probectl_probe_success", map[string]string{"tenant_id": "t1"})
	if len(got) == 0 || got[0].Value != 1 {
		t.Errorf("result not queryable in TSDB: %+v", got)
	}
}

// TestConsumerWritesEndpointResults proves the S37 follow-up: a DEM result
// published on probectl.endpoint.results flows through the same pipeline into the
// TSDB (the endpoint topic is no longer orphaned).
func TestConsumerWritesEndpointResults(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	b := bus.NewMemory()
	defer b.Close()
	w := tsdb.NewMemory()
	c := NewConsumer(b, w, "test", logging.New(io.Discard, "error", "json")).WithTenantBinding(allowAllBinding{})

	done := make(chan struct{})
	go func() { _ = c.Run(ctx); close(done) }()
	// TEST-002: synchronize on the endpoint subscription instead of a fixed sleep.
	if !b.WaitForSubscribers(ctx, bus.EndpointResultsTopic, 1) {
		t.Fatal("consumer did not subscribe to the endpoint results topic")
	}

	payload, err := proto.Marshal(&resultv1.Result{
		TenantId: "t9", AgentId: "laptop-1", CanaryType: "endpoint.attribution", Success: false,
		Attributes: map[string]string{"endpoint.cause": "wifi"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Publish(ctx, bus.EndpointResultsTopic, []byte("t9"), payload); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(w.Query("probectl_probe_success", map[string]string{"tenant_id": "t9"})) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	got := w.Query("probectl_probe_success", map[string]string{"tenant_id": "t9", "canary_type": "endpoint.attribution"})
	if len(got) == 0 {
		t.Fatalf("endpoint result not queryable in TSDB")
	}
	if got[0].Value != 0 { // Success=false → probe_success 0
		t.Errorf("expected success=0 for the failed attribution, got %v", got[0].Value)
	}
}
