// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package perf

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// fullStackScale resolves the tier, scale, and timeout a full-stack gate run
// uses: CI scale by default, reference scale 1 under PROBECTL_SCALE=1.
func fullStackScale() (tier Tier, scale float64, timeout time.Duration) {
	tier = Tier(os.Getenv("PROBECTL_SCALE_TIER"))
	if tier == "" {
		tier = TierS
	}
	scale = 0.05
	timeout = 10 * time.Minute
	if os.Getenv("PROBECTL_SCALE") == "1" {
		scale = 1
		timeout = 55 * time.Minute
		if tier == TierXXL {
			timeout = 3 * time.Hour
		}
	}
	return tier, scale, timeout
}

// TestFullStackLoadGate is the U-005 entry point for BOTH runs of the
// full-stack gate (agents → Kafka → consumer → Prometheus → query):
//
//   - `make load-test-smoke` — S tier at CI scale against the dev compose
//     stack (the load-smoke ci job): proves the harness on every pass.
//   - `make load-test TIER=L|XL|XXL` — scale 1 on reference hardware: the
//     human-scheduled run; copy the logged report row into
//     docs/scale-gate.md and flip the SLO labels from PROVISIONAL.
//
// The gate runs whenever the stack is DECLARED present (PROBECTL_RUN_FULLSTACK_LOAD=1,
// the nightly and the make targets set it). It then FAILS — never skips — if
// the declared endpoints are unset or the declared Kafka is unreachable, so a
// step that brought the stack up can never pass vacuously (TQ-04). A plain
// local `go test` with no declared stack SKIPS with a visible marker.
func TestFullStackLoadGate(t *testing.T) {
	declared := os.Getenv(fullStackDeclaredEnv) == "1"
	brokers := testsupport.KafkaBrokers()
	prom := os.Getenv("PROBECTL_PROM_URL")
	tier, scale, timeout := fullStackScale()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	targets := FullStackTargets{Brokers: brokers, PromURL: prom}
	runFullStackGateHarness(t, "full-stack load gate", declared, len(brokers) > 0 && prom != "",
		func() error { return probeFullStackKafka(ctx, brokers) },
		func() (fullStackGateResult, error) {
			rep, err := runFullStackGate(ctx, tier, scale, targets)
			if err != nil {
				return fullStackGateResult{}, err
			}
			return fullStackGateResult{
				resultRow:  rep.String(),
				detail:     []string{fmt.Sprintf("ingest detail: %s", rep.Scale.Ingest), rep.diagnostics()},
				violations: rep.Scale.Violations,
			}, nil
		})
}

// TestFullStackFlowGate is the SCALE-001 real-stack flow entry point:
// synthetic flow collectors → Kafka → production FlowConsumer → ClickHouse →
// tenant-scoped TopTalkers queries. It proves completeness, insert latency,
// query p95, and ClickHouse active-part pressure on the real flow stack, with
// the same declared-present precondition as the load gate (TQ-04).
func TestFullStackFlowGate(t *testing.T) {
	declared := os.Getenv(fullStackDeclaredEnv) == "1"
	brokers := testsupport.KafkaBrokers()
	flowURL := os.Getenv("PROBECTL_FLOWSTORE_URL")
	tier, scale, timeout := fullStackScale()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	targets := FullStackFlowTargets{Brokers: brokers, FlowStoreURL: flowURL}
	runFullStackGateHarness(t, "full-stack flow gate", declared, len(brokers) > 0 && flowURL != "",
		func() error { return probeFullStackKafka(ctx, brokers) },
		func() (fullStackGateResult, error) {
			rep, err := runFullStackFlowGate(ctx, tier, scale, targets)
			if err != nil {
				return fullStackGateResult{}, err
			}
			return fullStackGateResult{
				resultRow:  rep.String(),
				detail:     []string{fmt.Sprintf("flow insert latency: %s", rep.InsertLatency), rep.diagnostics()},
				violations: rep.Violations,
			}, nil
		})
}
