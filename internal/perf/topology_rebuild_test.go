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
)

func TestTopologyRebuildTargets(t *testing.T) {
	for _, tier := range []Tier{TierS, TierM, TierL} {
		target, err := TopologyRebuildTargetFor(tier)
		if err != nil {
			t.Fatal(err)
		}
		rep := DriveTopologyRebuild(target)
		t.Logf("TOPOLOGY_REBUILD_RESULT %s", rep)
		if len(rep.Violations) > 0 {
			t.Fatalf("topology rebuild target %s failed:\n%s", tier, strings.Join(rep.Violations, "\n"))
		}
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
