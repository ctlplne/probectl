//go:build integration

package perf

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestFullStackLoadGate is the U-005 entry point for BOTH runs of the
// full-stack gate (agents → Kafka → consumer → Prometheus → query):
//
//   - `make load-test-smoke` — S tier at CI scale against the dev compose
//     stack (the load-smoke ci job): proves the harness on every pass.
//   - `make load-test TIER=L|XL` — scale 1 on reference hardware: the
//     human-scheduled run; copy the logged report row into
//     docs/scale-gate.md and flip the SLO labels from PROVISIONAL.
//
// Skips without a real stack (PROBECTL_TEST_KAFKA + PROBECTL_PROM_URL), so
// the service-free integration/coverage jobs are unaffected. Run against a
// FRESH stack (`make compose-up`).
func TestFullStackLoadGate(t *testing.T) {
	brokers := os.Getenv("PROBECTL_TEST_KAFKA")
	prom := os.Getenv("PROBECTL_PROM_URL")
	if brokers == "" || prom == "" {
		t.Skip("PROBECTL_TEST_KAFKA / PROBECTL_PROM_URL not set — the full-stack load gate needs the real stack (make compose-up)")
	}

	tier := Tier(os.Getenv("PROBECTL_SCALE_TIER"))
	if tier == "" {
		tier = TierS
	}
	scale := 0.05
	timeout := 10 * time.Minute
	if os.Getenv("PROBECTL_SCALE") == "1" {
		scale = 1
		timeout = 55 * time.Minute
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	rep, err := RunFullStackGate(ctx, tier, scale, FullStackTargets{
		Brokers: strings.Split(brokers, ","),
		PromURL: prom,
	})
	if err != nil {
		t.Fatalf("full-stack gate %s: %v", tier, err)
	}
	t.Logf("RESULT ROW (docs/scale-gate.md): %s", rep)
	t.Logf("ingest detail: %s", rep.Scale.Ingest)
	t.Logf("%s", rep.Diagnostics())

	if len(rep.Scale.Violations) > 0 {
		t.Fatalf("FULL-STACK GATE FAILED:\n%s\n%s", rep.Diagnostics(), strings.Join(rep.Scale.Violations, "\n"))
	}
}
