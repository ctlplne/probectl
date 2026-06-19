// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

// ingestSmokeConfig is the CI-cheap single-deployment ingest scenario: a few
// tenants' worth of agents/tests producing a sustained result stream. Kept small
// enough to be a smoke (sub-second), large enough to be a meaningful baseline.
func ingestSmokeConfig() IngestConfig {
	return IngestConfig{
		Tenants:         4,
		AgentsPerTenant: 5,
		TestsPerAgent:   5,
		ResultsPerTest:  20, // 4*5*5*20 = 2000 results → 6000 series
		Producers:       8,
		SettleTimeout:   20 * time.Second,
	}
}

// TestIngestBaseline drives the lightweight agents → bus → consumer → TSDB path
// under load and asserts: (1) every result is ingested (correctness), (2) each
// tenant's series land under its own tenant_id (no cross-tenant mixing), and
// (3) throughput stays above the GA floor (regression guard).
func TestIngestBaseline(t *testing.T) {
	b := bus.NewMemory()
	defer b.Close()
	w := tsdb.NewMemory()
	cfg := ingestSmokeConfig()

	rep, err := DriveIngest(context.Background(), b, w, w.Len, cfg)
	if err != nil {
		t.Fatalf("drive ingest: %v", err)
	}
	t.Logf("%s", rep)

	if want := cfg.TotalResults() * seriesPerResult; rep.SeriesWritten != want {
		t.Fatalf("series written = %d, want %d (incomplete ingest)", rep.SeriesWritten, want)
	}

	// Per-tenant correctness: each tenant contributes exactly agents*tests*results
	// success series, all tagged with its own tenant_id.
	perTenant := cfg.AgentsPerTenant * cfg.TestsPerAgent * cfg.ResultsPerTest
	for tn := 0; tn < cfg.Tenants; tn++ {
		tid := fmt.Sprintf("tenant-%04d", tn)
		got := len(w.Query("probectl_probe_success", map[string]string{"tenant_id": tid}))
		if got != perTenant {
			t.Errorf("tenant %s: %d success series, want %d", tid, got, perTenant)
		}
	}

	if v := M6Baseline().CheckIngest(rep); len(v) > 0 {
		t.Errorf("ingest baseline violated: %v", v)
	}
}

// TestIngestEmptyScenario guards the obvious misuse.
func TestIngestEmptyScenario(t *testing.T) {
	b := bus.NewMemory()
	defer b.Close()
	w := tsdb.NewMemory()
	if _, err := DriveIngest(context.Background(), b, w, w.Len, IngestConfig{}); err == nil {
		t.Fatal("empty scenario should error")
	}
}

func TestBuildIdentitiesUsesDistinctSampleMillis(t *testing.T) {
	ids := buildIdentities(IngestConfig{
		Tenants: 1, AgentsPerTenant: 1, TestsPerAgent: 1, ResultsPerTest: 8,
	})
	if len(ids) != 8 {
		t.Fatalf("identities = %d, want 8", len(ids))
	}
	seen := map[int64]struct{}{}
	now := time.Now().UnixMilli()
	for _, id := range ids {
		ms := id.eventUnixNano / int64(time.Millisecond)
		if ms > now {
			t.Fatalf("synthetic event time is future-dated: %d > %d", ms, now)
		}
		if _, ok := seen[ms]; ok {
			t.Fatalf("duplicate synthetic sample millisecond %d", ms)
		}
		seen[ms] = struct{}{}
	}
}
