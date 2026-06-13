// SPDX-License-Identifier: LicenseRef-probectl-TBD

package pipeline

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/usage"
)

// meterSpy captures usage.Record calls so a test can assert what was metered.
type meterSpy struct {
	mu sync.Mutex
	m  map[string]int64 // tenant|meter -> sum
}

func newMeterSpy() *meterSpy { return &meterSpy{m: map[string]int64{}} }
func (s *meterSpy) Record(tenant, meter string, delta int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[tenant+"|"+meter] += delta
}
func (s *meterSpy) count(tenant, meter string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[tenant+"|"+meter]
}

// alwaysFailWriter fails every write permanently-style (transient → exhausts
// retries → dead-letter).
type alwaysFailWriter struct{}

func (alwaysFailWriter) Write(context.Context, []tsdb.Series) error {
	return errors.New("store down")
}
func (alwaysFailWriter) Close() error { return nil }

func resultMsg(t *testing.T, tenant, agent string) bus.Message {
	t.Helper()
	raw, err := proto.Marshal(&resultv1.Result{TenantId: tenant, AgentId: agent, CanaryType: "icmp", Success: true})
	if err != nil {
		t.Fatal(err)
	}
	return bus.Message{Topic: bus.NetworkResultsTopic, Key: []byte(tenant), Value: raw}
}

// CORRECT-005: result metering must count STORED results, not ingested-and-
// accepted ones. Before the fix usage.Record fired before the cardinality
// filter and before the write, so a cardinality-dropped result and a
// dead-lettered result were each metered as 1 result_ingested. After the fix
// metering happens only after a confirmed store write (matching the flow
// plane), so both record ZERO.
func TestMeteringIsStoredOnly(t *testing.T) {
	spy := newMeterSpy()
	usage.SetRecorder(spy)
	t.Cleanup(func() { usage.SetRecorder(nil) })

	log := logging.New(io.Discard, "error", "json")
	ctx := context.Background()

	t.Run("cardinality_dropped_is_not_metered", func(t *testing.T) {
		w := tsdb.NewMemory()
		// Tenant cap = 2: the warm-up result's two base series (success +
		// duration for agent a1) fill it. A result from a DIFFERENT agent then
		// presents two NEW identities (distinct agent_id label) — both exceed the
		// tenant cap and are dropped, so nothing stores.
		c := NewConsumer(bus.NewMemory(), w, "test", log).WithCardinalityCaps(0, 2)

		if err := c.handle(ctx, resultMsg(t, "t-drop", "a1")); err != nil {
			t.Fatalf("warm-up handle: %v", err)
		}
		warm := spy.count("t-drop", usage.MeterResultsIngested)
		if warm != 1 {
			t.Fatalf("warm-up stored result should meter 1, got %d", warm)
		}
		// This one is fully cardinality-dropped.
		if err := c.handle(ctx, resultMsg(t, "t-drop", "a2")); err != nil {
			t.Fatalf("dropped handle: %v", err)
		}
		if got := spy.count("t-drop", usage.MeterResultsIngested); got != warm {
			t.Fatalf("cardinality-dropped result was metered: count moved from %d to %d (want unchanged)", warm, got)
		}
	})

	t.Run("dead_lettered_is_not_metered", func(t *testing.T) {
		b := bus.NewMemory() // a real bus so the DLQ publish succeeds
		c := NewConsumer(b, alwaysFailWriter{}, "test", log)
		c.retryBase = time.Microsecond
		c.sleep = func(context.Context, time.Duration) {}

		if err := c.handle(ctx, resultMsg(t, "t-dlq", "a1")); err != nil {
			t.Fatalf("handle: %v", err)
		}
		if c.Stats().DeadLettered == 0 {
			t.Fatal("expected the result to be dead-lettered")
		}
		if got := spy.count("t-dlq", usage.MeterResultsIngested); got != 0 {
			t.Fatalf("dead-lettered result was metered: results_ingested=%d, want 0", got)
		}
		if got := spy.count("t-dlq", usage.MeterIngestBytes); got != 0 {
			t.Fatalf("dead-lettered result metered bytes=%d, want 0", got)
		}
	})

	t.Run("stored_result_is_metered", func(t *testing.T) {
		c := NewConsumer(bus.NewMemory(), tsdb.NewMemory(), "test", log)
		if err := c.handle(ctx, resultMsg(t, "t-ok", "a1")); err != nil {
			t.Fatalf("handle: %v", err)
		}
		if got := spy.count("t-ok", usage.MeterResultsIngested); got != 1 {
			t.Fatalf("stored result not metered: results_ingested=%d, want 1", got)
		}
	})
}
