// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"io"
	"log/slog"
	"testing"
)

// A source exposing the optional FilteredNonIPv4() (the live source does).
// The method name is legacy; it now counts unsupported address families while
// IPv6 is captured.
type filteringSource struct {
	sliceSource
	filtered uint64
}

func (s *filteringSource) FilteredNonIPv4() uint64 { return s.filtered }

func TestAggregatorFilteredNonIPv4(t *testing.T) {
	a := NewAggregator()
	if a.Stats().FilteredNonIPv4 != 0 {
		t.Fatal("new aggregator should report 0 filtered")
	}
	a.RecordFilteredNonIPv4(3)
	a.RecordFilteredNonIPv4(2)
	if got := a.Stats().FilteredNonIPv4; got != 5 {
		t.Fatalf("filtered = %d, want 5", got)
	}
}

// The agent folds the source's cumulative in-kernel unsupported-family filter
// count into its telemetry as a DELTA.
func TestAgentSyncsFilteredNonIPv4(t *testing.T) {
	cfg := Default()
	cfg.TenantID = "t1"
	src := &filteringSource{}
	a := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), src, NopEnricher{}, &captureEmitter{})

	src.filtered = 4
	a.syncFilteredNonIPv4()
	if got := a.agg.Stats().FilteredNonIPv4; got != 4 {
		t.Fatalf("after first sync = %d, want 4", got)
	}
	// Cumulative source counter advances; only the delta is folded.
	src.filtered = 10
	a.syncFilteredNonIPv4()
	if got := a.agg.Stats().FilteredNonIPv4; got != 10 {
		t.Fatalf("after second sync = %d, want 10", got)
	}
	// A source without the method (the fixture path) is simply skipped.
	a2 := newAgentWith(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), &sliceSource{}, NopEnricher{}, &captureEmitter{})
	a2.syncFilteredNonIPv4() // must not panic
	if a2.agg.Stats().FilteredNonIPv4 != 0 {
		t.Fatal("source without FilteredNonIPv4 must contribute 0")
	}
}
