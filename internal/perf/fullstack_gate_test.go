// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package perf

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

// fakeGateTB records the harness's terminal verdict without aborting the
// goroutine the way real t.Fatalf/t.Skipf do (Goexit), so one test can assert
// all three outcomes in sequence.
type fakeGateTB struct {
	logs    []string
	skipped bool
	fatal   bool
}

func (f *fakeGateTB) Helper() {}
func (f *fakeGateTB) Logf(format string, args ...any) {
	f.logs = append(f.logs, fmt.Sprintf(format, args...))
}
func (f *fakeGateTB) Skipf(format string, args ...any) {
	f.skipped = true
	f.Logf("SKIP "+format, args...)
}
func (f *fakeGateTB) Fatalf(format string, args ...any) {
	f.fatal = true
	f.Logf("FATAL "+format, args...)
}

// resultRow reports whether a RESULT ROW line carrying the given verdict was
// emitted — the exact signal the nightly greps for.
func (f *fakeGateTB) resultRow(verdict string) bool {
	for _, l := range f.logs {
		if strings.Contains(l, resultRowPrefix) && strings.Contains(l, verdict) {
			return true
		}
	}
	return false
}

// unreachableBus is a stopped Kafka without a broker: its broker-health probe
// fails. It satisfies bus.Bus plus the Healthy() seam probeBusReachable asserts
// for, so "Kafka down" is deterministic in CI.
type unreachableBus struct{ err error }

func (*unreachableBus) Publish(context.Context, string, []byte, []byte) error { return nil }
func (*unreachableBus) Subscribe(context.Context, string, string, bus.Handler) error {
	return nil
}
func (*unreachableBus) Close() error                    { return nil }
func (b *unreachableBus) Healthy(context.Context) error { return b.err }

// TestFullStackGateFailsClosedWhenDeclaredStackUnreachable is the TQ-04
// regression proof. The nightly "M-tier FULL-STACK regression" step brings
// Kafka up, so a gate that SKIPS or PASSES while Kafka is actually DOWN is the
// vacuous green the finding removed. This drives the SAME harness the nightly
// runs (runFullStackGateHarness), with an INJECTED unreachable bus and no
// broker, and asserts the gate FAILS and still leaves a RESULT ROW. It also
// pins the two honest paths: a reachable stack runs the REAL driver and PASSES
// with a RESULT ROW; an undeclared stack SKIPS with a VISIBLE marker.
//
// Non-vacuity: revert only the probe-fail branch of runFullStackGateHarness to
// a skip (the pre-fix always-skip behavior) and case 1 fails — the "Kafka down"
// run goes back to skip/pass, which this assertion catches.
func TestFullStackGateFailsClosedWhenDeclaredStackUnreachable(t *testing.T) {
	// 1) declared present + Kafka DOWN => FAIL + RESULT ROW, never skip/pass.
	down := &fakeGateTB{}
	downBus := &unreachableBus{err: errors.New("dial tcp 127.0.0.1:9092: connect: connection refused")}
	reached := false
	runFullStackGateHarness(down, "full-stack load gate", true, true,
		func() error { return probeBusReachable(context.Background(), downBus) },
		func() (fullStackGateResult, error) {
			reached = true
			return fullStackGateResult{resultRow: "unexpected PASS"}, nil
		})
	if reached {
		t.Fatal("TQ-04: measured run executed though Kafka was unreachable — precondition did not fail closed")
	}
	if !down.fatal {
		t.Fatalf("TQ-04: gate did not FAIL with the declared stack's Kafka unreachable: %v", down.logs)
	}
	if down.skipped {
		t.Fatal("TQ-04: gate SKIPPED a declared-present-but-unreachable stack — the vacuous green the finding removed")
	}
	if !down.resultRow("FAIL") {
		t.Fatalf("TQ-04: no RESULT ROW emitted on the unreachable path: %v", down.logs)
	}

	// 2) declared present + Kafka UP => the REAL driver runs on a memory stack
	// and the gate PASSES with a RESULT ROW.
	profile, err := ProfileFor(TierM, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	memBus := bus.NewMemory()
	defer memBus.Close()
	w := tsdb.NewMemory()
	up := &fakeGateTB{}
	runFullStackGateHarness(up, "full-stack load gate", true, true,
		func() error { return probeBusReachable(context.Background(), memBus) },
		func() (fullStackGateResult, error) {
			rep, err := DriveFullStack(context.Background(), memBus, w, memCounter(w, withNS(profile.Ingest, "lsreg")), profile, true, "lsreg")
			if err != nil {
				return fullStackGateResult{}, err
			}
			return fullStackGateResult{resultRow: rep.String(), violations: rep.Scale.Violations}, nil
		})
	if up.fatal || up.skipped {
		t.Fatalf("a reachable, healthy run must neither fail nor skip: %v", up.logs)
	}
	if !up.resultRow("PASS") {
		t.Fatalf("reachable run left no RESULT ROW ... PASS: %v", up.logs)
	}

	// 3) NOT declared (a local `go test`) => visible SKIP marker, never silent.
	local := &fakeGateTB{}
	runFullStackGateHarness(local, "full-stack load gate", false, false,
		func() error {
			t.Fatal("probe ran for an undeclared stack")
			return nil
		},
		func() (fullStackGateResult, error) {
			t.Fatal("measured run ran for an undeclared stack")
			return fullStackGateResult{}, nil
		})
	if !local.skipped {
		t.Fatalf("undeclared stack did not skip: %v", local.logs)
	}
	if local.fatal {
		t.Fatalf("undeclared stack must not fail: %v", local.logs)
	}
	if !local.resultRow("SKIP") {
		t.Fatalf("undeclared skip is not a VISIBLE RESULT ROW/SKIP marker: %v", local.logs)
	}
}

// TestProbeBusReachableFailsClosedButToleratesNoHealthSeam pins the reachability
// seam itself: a bus that reports an unhealthy broker surfaces that error (fail
// closed), while a bus with no health seam (the in-memory test bus) is treated
// as reachable so unit stacks are not forced to implement it.
func TestProbeBusReachableFailsClosedButToleratesNoHealthSeam(t *testing.T) {
	boom := errors.New("broker unreachable")
	if err := probeBusReachable(context.Background(), &unreachableBus{err: boom}); !errors.Is(err, boom) {
		t.Fatalf("unreachable bus must surface its health error, got %v", err)
	}
	mem := bus.NewMemory()
	defer mem.Close()
	if err := probeBusReachable(context.Background(), mem); err != nil {
		t.Fatalf("a bus with no health seam must read as reachable, got %v", err)
	}
}
