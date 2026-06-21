// SPDX-License-Identifier: LicenseRef-probectl-TBD

package chaos

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestDependencyDrillPrintsCounters(t *testing.T) {
	if os.Getenv("PROBECTL_CHAOS_DRILL_TEST_WORKER") == "1" {
		if err := RunDependencyDrillWorker(os.Stdin, os.Stdout, 150*time.Millisecond); err != nil {
			t.Fatal(err)
		}
		return
	}

	var out bytes.Buffer
	res, err := RunDependencyDrill(context.Background(), &out, DependencyDrillOptions{
		TempDir:       t.TempDir(),
		WorkerCommand: []string{os.Args[0], "-test.run=TestDependencyDrillPrintsCounters"},
		WorkerEnv:     append(os.Environ(), "PROBECTL_CHAOS_DRILL_TEST_WORKER=1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.DiskFullRejected == 0 || res.DiskFullDropped == 0 || res.DiskFullRecoveryDrained != res.DiskFullEnqueued {
		t.Fatalf("disk-full counters did not prove bounded recovery: %+v", res)
	}
	if res.MemoryPressureDropped == 0 || res.MemoryQuietAdmitted == 0 {
		t.Fatalf("memory-pressure counters did not prove noisy/quiet isolation: %+v", res)
	}
	if res.PodKillKilled != 1 || res.PodKillRestarts != 1 || res.PodKillRequeued != 1 || res.PodKillRecoveredAcks < 2 {
		t.Fatalf("pod-kill counters did not prove restart/requeue: %+v", res)
	}
	if res.DependencyOutageFailed != 1 || res.DependencyRecovered != 1 {
		t.Fatalf("dependency-outage counters did not prove recovery: %+v", res)
	}
	line := out.String()
	for _, want := range []string{
		"CHAOS_DEPENDENCY_RESULT",
		"disk_full_rejected=",
		"memory_pressure_dropped=",
		"pod_kill_restarts=",
		"dependency_outage_failed=",
		"dependency_recovered=",
		"recovery_assertions=4",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("result line %q missing %q", line, want)
		}
	}
}
