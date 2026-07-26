// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package perf

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestTopologyRebuildTargets(t *testing.T) {
	for _, tier := range []Tier{TierS, TierM, TierL} {
		target, err := TopologyRebuildTargetFor(tier)
		if err != nil {
			t.Fatal(err)
		}
		rep := driveTopologyRebuildCIGate(target)
		t.Logf("TOPOLOGY_REBUILD_RESULT %s", rep)
		if len(rep.Violations) > 0 {
			t.Fatalf("topology rebuild target %s failed:\n%s", tier, strings.Join(rep.Violations, "\n"))
		}
	}
}

func TestTopologyRebuildGateAbsorbsOneSchedulerPause(t *testing.T) {
	target, err := TopologyRebuildTargetFor(TierM)
	if err != nil {
		t.Fatal(err)
	}
	healthy := topologyRebuildTimingSample(target, target.MaxReplayP95/2, target.MaxSnapshotP95/2, target.MaxTotal/2)
	paused := topologyRebuildTimingSample(target, target.MaxReplayP95*10, target.MaxSnapshotP95*10, target.MaxTotal*10)
	paused.Violations = topologyRebuildTimingViolations(
		target, paused.ReplayLatency.P95, paused.SnapshotLatency.P95, paused.Elapsed)

	rep := evaluateTopologyRebuildGate(target, []TopologyRebuildReport{healthy, paused, healthy})
	if len(rep.Violations) > 0 {
		t.Fatalf("one injected scheduler pause must not fail the median timing gate: %v", rep.Violations)
	}
	if !strings.Contains(rep.String(), topologyRebuildCIAggregationRule) ||
		!strings.Contains(rep.String(), paused.SnapshotLatency.P95.String()) {
		t.Fatalf("receipt must log its aggregation rule and raw paused sample: %s", rep)
	}
}

func TestTopologyRebuildGateRejectsSustainedSlowdown(t *testing.T) {
	target, err := TopologyRebuildTargetFor(TierM)
	if err != nil {
		t.Fatal(err)
	}
	slow := topologyRebuildTimingSample(
		target, target.MaxReplayP95/2, target.MaxSnapshotP95+time.Millisecond, target.MaxTotal/2)
	slow.Violations = topologyRebuildTimingViolations(
		target, slow.ReplayLatency.P95, slow.SnapshotLatency.P95, slow.Elapsed)

	rep := evaluateTopologyRebuildGate(target, []TopologyRebuildReport{slow, slow, slow})
	if len(rep.Violations) != 1 ||
		!strings.Contains(rep.Violations[0], "median-of-3 M snapshot p95") {
		t.Fatalf("planted sustained snapshot slowdown must fail the median timing gate: %v", rep.Violations)
	}
}

func TestTopologyRebuildGateRequiresEverySampleCorrect(t *testing.T) {
	target, err := TopologyRebuildTargetFor(TierM)
	if err != nil {
		t.Fatal(err)
	}
	healthy := topologyRebuildTimingSample(target, time.Millisecond, time.Millisecond, time.Millisecond)
	broken := healthy
	broken.CorrectnessViolations = []string{"tenant-b rebuilt 0 edges, want 400"}

	rep := evaluateTopologyRebuildGate(target, []TopologyRebuildReport{healthy, broken, healthy})
	if len(rep.Violations) != 1 || !strings.Contains(rep.Violations[0], "sample 2 correctness") {
		t.Fatalf("one incorrect topology sample must fail closed: %v", rep.Violations)
	}
}

func TestTopologyRebuildReferenceRunRemainsStrict(t *testing.T) {
	target, err := TopologyRebuildTargetFor(TierS)
	if err != nil {
		t.Fatal(err)
	}
	target.MaxReplayP95 = time.Nanosecond
	target.MaxSnapshotP95 = time.Nanosecond
	target.MaxTotal = time.Nanosecond

	rep := DriveTopologyRebuild(target)
	if len(rep.Violations) != 3 {
		t.Fatalf("strict single-run reference driver must enforce every timing ceiling: %v", rep.Violations)
	}
}

func topologyRebuildTimingSample(
	target TopologyRebuildTarget,
	replayP95, snapshotP95, total time.Duration,
) TopologyRebuildReport {
	return TopologyRebuildReport{
		Target:          target,
		ReplayLatency:   LatencyStat{P95: replayP95},
		SnapshotLatency: LatencyStat{P95: snapshotP95},
		Elapsed:         total,
	}
}

func TestTopologyRebuildTargetsCoverAllTiers(t *testing.T) {
	for _, tier := range []Tier{TierS, TierM, TierL, TierXL, TierXXL} {
		target, err := TopologyRebuildTargetFor(tier)
		if err != nil {
			t.Fatal(err)
		}
		if target.Observations() <= 0 || target.MaxReplayP95 <= 0 || target.MaxSnapshotP95 <= 0 || target.MaxTotal <= 0 {
			t.Fatalf("%s target incomplete: %+v", tier, target)
		}
	}
}

func BenchmarkTopologyRebuild(b *testing.B) {
	tier := Tier(os.Getenv("PROBECTL_SCALE_TIER"))
	if tier == "" {
		tier = TierL
	}
	target, err := TopologyRebuildTargetFor(tier)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rep := DriveTopologyRebuild(target)
		if len(rep.Violations) > 0 {
			b.Fatalf("topology rebuild target %s failed: %s", tier, strings.Join(rep.Violations, "\n"))
		}
	}
}
