// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package perf

import (
	"context"
	"os"
	"strings"
	"testing"

	"time"

	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestFullStackLoadGate is the U-005 entry point for BOTH runs of the
// full-stack gate (agents → Kafka → consumer → Prometheus → query):
//
//   - `make load-test-smoke` — S tier at CI scale against the dev compose
//     stack (the load-smoke ci job): proves the harness on every pass.
//   - `make load-test TIER=L|XL|XXL` — scale 1 on reference hardware: the
//     human-scheduled run; copy the logged report row into
//     docs/scale-gate.md and flip the SLO labels from PROVISIONAL.
//
// Skips without a real stack (PROBECTL_TEST_KAFKA + PROBECTL_PROM_URL), so
// the service-free integration/coverage jobs are unaffected. Run against a
// FRESH stack (`make compose-up`).
func TestFullStackLoadGate(t *testing.T) {
	if os.Getenv("PROBECTL_RUN_FULLSTACK_LOAD") != "1" {
		testsupport.SkipOptIn(t, "PROBECTL_RUN_FULLSTACK_LOAD", "the full-stack load gate runs via make load-test-smoke")
	}
	brokers := os.Getenv("PROBECTL_TEST_KAFKA")
	prom := os.Getenv("PROBECTL_PROM_URL")
	if brokers == "" || prom == "" {
		testsupport.SkipOptIn(t, "PROBECTL_RUN_FULLSTACK_LOAD", "the full-stack load gate runs via make load-test-smoke")
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
		if tier == TierXXL {
			timeout = 3 * time.Hour
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	rep, err := runFullStackGate(ctx, tier, scale, FullStackTargets{
		Brokers: strings.Split(brokers, ","),
		PromURL: prom,
	})
	if err != nil {
		t.Fatalf("full-stack gate %s: %v", tier, err)
	}
	t.Logf("RESULT ROW (docs/scale-gate.md): %s", rep)
	t.Logf("ingest detail: %s", rep.Scale.Ingest)
	t.Logf("%s", rep.diagnostics())

	if len(rep.Scale.Violations) > 0 {
		t.Fatalf("FULL-STACK GATE FAILED:\n%s\n%s", rep.diagnostics(), strings.Join(rep.Scale.Violations, "\n"))
	}
}

// TestFullStackFlowGate is the SCALE-001 real-stack flow entry point:
// synthetic flow collectors → Kafka → production FlowConsumer → ClickHouse →
// tenant-scoped TopTalkers queries. It proves completeness, insert latency,
// query p95, and ClickHouse active-part pressure on the real flow stack.
func TestFullStackFlowGate(t *testing.T) {
	if os.Getenv("PROBECTL_RUN_FULLSTACK_LOAD") != "1" {
		testsupport.SkipOptIn(t, "PROBECTL_RUN_FULLSTACK_LOAD", "the full-stack load gate runs via make load-test-smoke")
	}
	brokers := os.Getenv("PROBECTL_TEST_KAFKA")
	flowURL := os.Getenv("PROBECTL_FLOWSTORE_URL")
	if brokers == "" || flowURL == "" {
		testsupport.SkipOptIn(t, "PROBECTL_RUN_FULLSTACK_LOAD", "the full-stack load gate runs via make load-test-smoke")
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
		if tier == TierXXL {
			timeout = 3 * time.Hour
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	rep, err := runFullStackFlowGate(ctx, tier, scale, FullStackFlowTargets{
		Brokers:      strings.Split(brokers, ","),
		FlowStoreURL: flowURL,
	})
	if err != nil {
		t.Fatalf("full-stack flow gate %s: %v", tier, err)
	}
	t.Logf("RESULT ROW (docs/scale-gate.md): %s", rep)
	t.Logf("flow insert latency: %s", rep.InsertLatency)
	t.Logf("%s", rep.diagnostics())

	if len(rep.Violations) > 0 {
		t.Fatalf("FULL-STACK FLOW GATE FAILED:\n%s\n%s", rep.diagnostics(), strings.Join(rep.Violations, "\n"))
	}
}
