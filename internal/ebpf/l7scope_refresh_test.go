// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type scopeHealthL7Source struct {
	degraded bool
}

func (s scopeHealthL7Source) L7Events(context.Context) (<-chan L7Event, error) {
	ch := make(chan L7Event)
	close(ch)
	return ch, nil
}

func (s scopeHealthL7Source) Drops() uint64             { return 0 }
func (s scopeHealthL7Source) Close() error              { return nil }
func (s scopeHealthL7Source) L7ScopeSyncDegraded() bool { return s.degraded }

func TestL7ScopeRefreshFailureIsObservable(t *testing.T) {
	var logs bytes.Buffer
	monitor := newL7ScopeSyncMonitor(
		&Config{TenantID: "tenant-a", Host: "edge-01"},
		slog.New(slog.NewTextHandler(&logs, nil)),
		scopeExe,
	)
	monitor.degradeAfter = 2

	syncErr := errors.New("proc walk denied")
	for i := 0; i < 2; i++ {
		if monitor.Refresh(func() error { return syncErr }) {
			t.Fatal("failing syncScope refresh reported success")
		}
	}

	if got := monitor.Failures(); got != 2 {
		t.Fatalf("l7_scope_sync_failures_total = %d, want 2", got)
	}
	if got := monitor.LastError(); got != syncErr.Error() {
		t.Fatalf("last error = %q, want %q", got, syncErr.Error())
	}
	if !monitor.Degraded() {
		t.Fatal("persistent l7 scope refresh failures should mark capture degraded")
	}

	logBody := logs.String()
	for _, want := range []string{
		"tenant_id=tenant-a",
		"host=edge-01",
		"scope_kind=exe",
		"l7_scope_sync_failures_total=2",
		"error=\"proc walk denied\"",
		"degraded=true",
	} {
		if !strings.Contains(logBody, want) {
			t.Fatalf("scope refresh failure log missing %q:\n%s", want, logBody)
		}
	}

	agg := NewAggregator()
	agg.RecordDropStats(DropStats{L7ScopeSyncFailures: monitor.Failures()})
	if got := agg.Stats().L7ScopeSyncFailures; got != 2 {
		t.Fatalf("aggregated l7_scope_sync_failures_total = %d, want 2", got)
	}

	a := newAgentWith(
		&Config{TenantID: "tenant-a", Host: "edge-01", FlushInterval: time.Hour},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		&sliceSource{},
		NopEnricher{},
		&captureEmitter{},
	)
	a.ready.Store(true)
	a.l7source = scopeHealthL7Source{degraded: true}
	if a.Ready() {
		t.Fatal("agent readiness stayed true despite degraded L7 scope refresh health")
	}

	monitor.Refresh(func() error { return nil })
	if monitor.Degraded() {
		t.Fatal("successful scope refresh should clear degraded readiness")
	}
}
