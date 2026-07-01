// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

import (
	"os"
	"strings"
	"testing"
)

func TestHotPathCatalogCoversAuditedSurfaces(t *testing.T) {
	required := []string{
		"hp-agent-control-checkin",
		"hp-results-latest",
		"hp-incident-feed",
		"hp-incident-correlation",
		"hp-probe-result-to-incident",
		"hp-flow-query",
		"hp-topology-read",
		"hp-topology-whatif",
		"hp-ai-ask",
		"hp-mcp-jsonrpc",
		"hp-otlp-http-ingest",
		"hp-prom-query",
	}
	for _, id := range required {
		if _, ok := HotPathByID(id); !ok {
			t.Errorf("missing audited hot-path SLO row %q", id)
		}
	}
}

func TestHotPathCatalogTargetsAndReceipts(t *testing.T) {
	seen := map[string]bool{}
	for _, hp := range HotPathCatalog() {
		if hp.ID == "" {
			t.Fatal("hot-path row with empty ID")
		}
		if seen[hp.ID] {
			t.Fatalf("duplicate hot-path ID %q", hp.ID)
		}
		seen[hp.ID] = true
		if hp.Name == "" || hp.Owner == "" {
			t.Errorf("%s: name and owner are required", hp.ID)
		}
		if len(hp.Surfaces) == 0 {
			t.Errorf("%s: at least one served surface is required", hp.ID)
		}
		for _, s := range hp.Surfaces {
			if s.Kind == "" || s.Method == "" || s.Pattern == "" {
				t.Errorf("%s: complete surface kind/method/pattern required: %+v", hp.ID, s)
			}
		}
		if hp.Targets.P50 <= 0 || hp.Targets.P95 <= 0 || hp.Targets.P99 <= 0 {
			t.Errorf("%s: p50/p95/p99 targets are all required", hp.ID)
		}
		if hp.Targets.P50 > hp.Targets.P95 || hp.Targets.P95 > hp.Targets.P99 {
			t.Errorf("%s: percentile ceilings must be ordered p50 <= p95 <= p99: %+v", hp.ID, hp.Targets)
		}
		if hp.Targets.MinThroughputPerSecond <= 0 {
			t.Errorf("%s: throughput floor is required", hp.ID)
		}
		if len(hp.Measurements) == 0 {
			t.Errorf("%s: at least one measurement receipt is required", hp.ID)
		}
		hasRunnable := false
		for _, m := range hp.Measurements {
			if m.Kind == "" || m.Receipt == "" || m.Source == "" {
				t.Errorf("%s: measurement needs kind, receipt, and source: %+v", hp.ID, m)
			}
			switch m.Kind {
			case MeasurementBenchmark, MeasurementLoadGate:
				if m.Command == "" {
					t.Errorf("%s: runnable measurement %q needs a command", hp.ID, m.Kind)
				}
				hasRunnable = true
			case MeasurementTrace:
				if !strings.Contains(m.Receipt, "duration_ms") {
					t.Errorf("%s: trace-derived receipt must name duration_ms, got %q", hp.ID, m.Receipt)
				}
				hasRunnable = true
			default:
				t.Errorf("%s: unknown measurement kind %q", hp.ID, m.Kind)
			}
		}
		if !hasRunnable {
			t.Errorf("%s: missing benchmark, load-gate, or trace-derived measurement", hp.ID)
		}
	}
}

func TestHotPathCatalogDocumented(t *testing.T) {
	b, err := os.ReadFile("../../docs/perf-hotpaths.md")
	if err != nil {
		t.Fatalf("read docs/perf-hotpaths.md: %v", err)
	}
	doc := string(b)
	for _, hp := range HotPathCatalog() {
		if !strings.Contains(doc, hp.ID) {
			t.Errorf("docs/perf-hotpaths.md missing hot-path ID %s", hp.ID)
		}
	}
}
