// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package perf

import (
	"context"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
)

// fullStackDeclaredEnv is how a harness DECLARES the real stack present for a
// full-stack regression run: the nightly "M-tier FULL-STACK regression" step
// and `make load-test-smoke` set it to 1. When it is set the gate MUST produce
// a verdict — a missing endpoint or an UNREACHABLE dependency is a hard FAIL,
// never a skip — because a step that brings Kafka/Prometheus/ClickHouse up and
// then passes by skipping is the exact vacuous green TQ-04 removed. Unset (a
// plain local `go test`) is the one sanctioned skip, and even then the gate
// emits a visible SKIP marker rather than a silent green. CONTRIBUTING.md.
const fullStackDeclaredEnv = "PROBECTL_RUN_FULLSTACK_LOAD"

// resultRowPrefix is the stdout marker the nightly greps for. Every terminal
// path of a full-stack gate — a PASS/FAIL measured run, a declared-but-
// unreachable FAIL, or a legitimate local SKIP — emits exactly one line that
// contains it, so a gate can never leave the log without a verdict (TQ-04).
const resultRowPrefix = "RESULT ROW"

// fullStackProbeTimeout bounds the reachability precondition. A declared-but-
// down broker must fail the gate PROMPTLY rather than hang until the outer load
// budget expires (which would read as a slow run, not a dependency outage).
const fullStackProbeTimeout = 15 * time.Second

// gateTB is the subset of *testing.T the full-stack gate harness uses. Taking
// an interface (not *testing.T) lets the TQ-04 regression test drive the exact
// run-vs-skip-vs-fail logic the nightly runs, with an injected recording fake,
// and assert the verdict deterministically — no real broker required.
type gateTB interface {
	Helper()
	Logf(format string, args ...any)
	Skipf(format string, args ...any)
	Fatalf(format string, args ...any)
}

// fullStackGateResult is a measured run's verdict for the harness: the RESULT
// ROW the operator copies into docs/scale-gate.md, extra diagnostic lines, and
// any SLO/materiality violations (a non-empty slice means the gate FAILS).
type fullStackGateResult struct {
	resultRow  string
	detail     []string
	violations []string
}

// runFullStackGateHarness is the single place that decides a full-stack
// regression gate's outcome, shared by the load and flow entry points so the
// policy cannot drift between them (TQ-04):
//
//   - stack NOT declared (fullStackDeclaredEnv != 1): the one sanctioned skip —
//     a local `go test` with no provisioned stack — emitted as a VISIBLE SKIP
//     RESULT ROW, never a silent green.
//   - declared present but its endpoints are unset, or the dependency is
//     unreachable (probe fails): FAIL CLOSED with a RESULT ROW. A step that
//     declared the stack present must not pass by skipping.
//   - declared present and reachable: run the measured gate and emit its RESULT
//     ROW; a run error or any SLO violation FAILS the gate.
func runFullStackGateHarness(t gateTB, gate string, declared, endpointsSet bool, probe func() error, run func() (fullStackGateResult, error)) {
	t.Helper()
	if !declared {
		t.Logf("%s: SKIP %s — %s!=1 (no real stack declared; a local `go test` legitimately skips, CI and the nightly set it to 1)", resultRowPrefix, gate, fullStackDeclaredEnv)
		t.Skipf("%s: %s!=1 — the full-stack gate runs only against a provisioned stack", gate, fullStackDeclaredEnv)
		return
	}
	if !endpointsSet {
		t.Logf("%s: %s FAIL — stack declared present (%s=1) but its endpoints are unset (fail closed, not skip)", resultRowPrefix, gate, fullStackDeclaredEnv)
		t.Fatalf("%s: stack declared present (%s=1) but its endpoints are unset", gate, fullStackDeclaredEnv)
		return
	}
	if err := probe(); err != nil {
		t.Logf("%s: %s FAIL — stack declared present (%s=1) but its dependency is unreachable: %v", resultRowPrefix, gate, fullStackDeclaredEnv, err)
		t.Fatalf("%s: dependency unreachable while the stack is declared present: %v", gate, err)
		return
	}
	res, err := run()
	if err != nil {
		t.Logf("%s: %s FAIL — measured run error: %v", resultRowPrefix, gate, err)
		t.Fatalf("%s: %v", gate, err)
		return
	}
	t.Logf("%s (docs/scale-gate.md): %s", resultRowPrefix, res.resultRow)
	for _, d := range res.detail {
		t.Logf("%s", d)
	}
	if len(res.violations) > 0 {
		t.Fatalf("%s FAILED:\n%s", gate, strings.Join(res.violations, "\n"))
	}
}

// probeBusReachable fails closed when a bus that can report broker health is
// unreachable, and treats a bus that cannot report health (the in-memory test
// bus) as reachable. It is the reachability seam the TQ-04 regression test
// drives with an injected unreachable fake bus. docs/guardrails.md G7-12.
func probeBusReachable(ctx context.Context, b bus.Bus) error {
	h, ok := b.(interface {
		Healthy(context.Context) error
	})
	if !ok {
		return nil
	}
	return h.Healthy(ctx)
}

// probeFullStackKafka opens a short-lived client to the DECLARED Kafka brokers
// and pings them within fullStackProbeTimeout, so a declared-but-down broker
// FAILS the gate promptly instead of hanging until the load budget expires
// (TQ-04). docs/guardrails.md G7-12.
func probeFullStackKafka(ctx context.Context, brokers []string) error {
	b, err := bus.NewKafka(brokers, 0)
	if err != nil {
		return err
	}
	defer b.Close()
	pctx, cancel := context.WithTimeout(ctx, fullStackProbeTimeout)
	defer cancel()
	return probeBusReachable(pctx, b)
}
