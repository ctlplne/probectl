// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"bytes"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/ebpf/l7"
)

// TestAgentL7MapsStayBounded drives the LIVE agent path (observeL7, the same
// method Run() calls per event) with far more distinct connections than the cap
// and asserts every per-connection map stays bounded and the eviction counters
// rise — EBPF-001 (the bounded maps are wired into the runtime) + FUZZ-001 (the
// L7 maps are capped). Pre-fix, l7conns / l7man.conns / the service map grew
// unbounded (cap=0 was never set from the runtime), so Len() would equal N.
func TestAgentL7MapsStayBounded(t *testing.T) {
	const (
		connCap = 64
		edgeCap = 64
		n       = 5000 // >> caps
	)
	cfg := &Config{
		TenantID:        "t1",
		Host:            "node-1",
		FlushInterval:   time.Hour,
		MaxL7Conns:      connCap,
		MaxServiceEdges: edgeCap,
		L7ConnIdleTTL:   5 * time.Minute,
	}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &sliceSource{}, NopEnricher{}, &captureEmitter{})

	base := time.Unix(0, 0)
	req := []byte("GET /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
	for i := 0; i < n; i++ {
		// Each connID is distinct AND each edge (src→dst) is distinct, so an
		// unbounded implementation would accumulate n entries in BOTH maps.
		a.observeL7(L7Event{
			ConnID:      uint64(i + 1),
			TenantID:    "t1",
			Source:      Endpoint{Workload: "client"},
			Destination: Endpoint{Workload: "svc", Port: uint32(10000 + i)},
			Transport:   "tcp",
			Data:        l7.DataEvent{Kind: l7.Request, Time: base.Add(time.Duration(i) * time.Millisecond), Payload: req},
		})
		// Fold a matching flow so the SERVICE map also sees distinct edges.
		a.observe(Flow{
			TenantID:    "t1",
			Source:      Endpoint{Workload: "client"},
			Destination: Endpoint{Workload: "svc", Port: uint32(10000 + i)},
			Transport:   "tcp",
			Observed:    base.Add(time.Duration(i) * time.Millisecond),
		})
	}

	if got := len(a.l7conns); got > connCap {
		t.Errorf("l7conns size = %d, exceeds cap %d (FUZZ-001: identity map unbounded)", got, connCap)
	}
	if got := a.l7man.Len(); got > connCap {
		t.Errorf("l7man.Len() = %d, exceeds cap %d (FUZZ-001: tracker map unbounded)", got, connCap)
	}
	if got := a.agg.ServiceMap().Len(); got > edgeCap {
		t.Errorf("service map Len() = %d, exceeds cap %d (EBPF-001: bounded map not wired into runtime)", got, edgeCap)
	}
	if a.L7Evicted() == 0 {
		t.Error("L7Evicted() == 0 — eviction never fired under N>>cap churn (bound not enforced)")
	}
	// l7man stays bounded because the agent's eviction closes its trackers in
	// lockstep (l7man.Close on evict), so l7man.Len() <= cap above is the proof;
	// l7man's OWN cap/eviction counter is exercised by l7.TestManagerCapBounded.
	if a.agg.ServiceMap().Evicted() == 0 {
		t.Error("ServiceMap.Evicted() == 0 — edge cap never enforced (EBPF-001 not wired)")
	}
}

// TestAgentL7IdleSweep verifies the flush-driven idle sweep abandons stale
// connections (FUZZ-001) — the runtime's continuous enforcement, not just the
// hard cap. It feeds a few connections, advances past the TTL, and asserts
// pruneL7 closes them (l7conns, l7man, and l7seen all drained).
func TestAgentL7IdleSweep(t *testing.T) {
	cfg := &Config{
		TenantID: "t1", Host: "n1", FlushInterval: time.Hour,
		MaxL7Conns: 1000, MaxServiceEdges: 1000, L7ConnIdleTTL: time.Minute,
	}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &sliceSource{}, NopEnricher{}, &captureEmitter{})

	base := time.Unix(0, 0)
	req := []byte("GET /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
	for i := 0; i < 10; i++ {
		a.observeL7(L7Event{
			ConnID: uint64(i + 1), TenantID: "t1",
			Source: Endpoint{Workload: "c"}, Destination: Endpoint{Workload: "s", Port: 8443}, Transport: "tcp",
			Data: l7.DataEvent{Kind: l7.Request, Time: base, Payload: req},
		})
	}
	if len(a.l7conns) != 10 {
		t.Fatalf("setup: l7conns = %d, want 10", len(a.l7conns))
	}

	// Advance well past the idle TTL and sweep.
	a.pruneL7(base.Add(5 * time.Minute))

	if len(a.l7conns) != 0 {
		t.Errorf("after idle sweep: l7conns = %d, want 0", len(a.l7conns))
	}
	if a.l7man.Len() != 0 {
		t.Errorf("after idle sweep: l7man.Len() = %d, want 0", a.l7man.Len())
	}
	if a.L7Evicted() < 10 {
		t.Errorf("after idle sweep: L7Evicted() = %d, want >= 10", a.L7Evicted())
	}
}

func TestFlushStatsIncludesEvictions(t *testing.T) {
	var logs bytes.Buffer
	cfg := &Config{
		TenantID:        "t1",
		Host:            "node-1",
		FlushInterval:   time.Hour,
		MaxL7Conns:      1,
		MaxServiceEdges: 1,
		L7ConnIdleTTL:   5 * time.Minute,
	}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(&logs, nil)), &sliceSource{}, NopEnricher{}, &captureEmitter{})

	base := time.Unix(0, 0)
	req := []byte("GET /x HTTP/1.1\r\nContent-Length: 0\r\n\r\n")
	observeConn := func(connID uint64, port uint32) {
		ts := base.Add(time.Duration(connID) * time.Millisecond)
		a.observeL7(L7Event{
			ConnID:      connID,
			TenantID:    "t1",
			Source:      Endpoint{Workload: "client"},
			Destination: Endpoint{Workload: "svc", Port: port},
			Transport:   "tcp",
			Data:        l7.DataEvent{Kind: l7.Request, Time: ts, Payload: req},
		})
		a.observe(Flow{
			TenantID:    "t1",
			Source:      Endpoint{Workload: "client"},
			Destination: Endpoint{Workload: "svc", Port: port},
			Transport:   "tcp",
			Observed:    ts,
		})
	}

	observeConn(1, 10001)
	observeConn(2, 10002)
	if a.L7Evicted() == 0 {
		t.Fatal("setup: agent L7 identity eviction did not fire")
	}
	if a.agg.ServiceMap().Evicted() == 0 {
		t.Fatal("setup: service-map eviction did not fire")
	}

	// Let the parser manager's own cap fire too. The agent identity cap already
	// proved its path above; disabling it here avoids pre-closing the manager
	// tracker before Manager.OnData can enforce its own cap.
	a.l7connsCap = 0
	a.l7man.SetBounds(1, 5*time.Minute)
	observeConn(3, 10003)
	observeConn(4, 10004)
	if a.l7man.Evicted() == 0 {
		t.Fatal("setup: L7 manager eviction did not fire")
	}

	a.logFlushStats("ebpf flows emitted", 0, 0, 0)
	logBody := logs.String()
	for _, want := range []string{
		"tenant_id=t1",
		"l7_evicted_total=",
		"service_map_evicted_total=",
		"l7_manager_evicted_total=",
	} {
		if !strings.Contains(logBody, want) {
			t.Fatalf("flush stats log missing %q:\n%s", want, logBody)
		}
	}
	if strings.Contains(logBody, "l7_evicted_total=0") ||
		strings.Contains(logBody, "service_map_evicted_total=0") ||
		strings.Contains(logBody, "l7_manager_evicted_total=0") {
		t.Fatalf("flush stats emitted a zero eviction counter after forced pressure:\n%s", logBody)
	}
}
