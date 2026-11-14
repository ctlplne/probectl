// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package shipped

import (
	"os"
	"testing"
	"time"
)

func TestRestartedSharedControlOutlivesInitiatingSubtest(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	stack := &Stack{Dir: t.TempDir(), owner: t}
	t.Run("restart", func(t *testing.T) {
		stack.startWithCleanupOwner(t, stack.owner, "restarted-control", binary,
			[]string{"-test.run=^TestShippedProcessLifetimeHelper$"},
			[]string{"PROBECTL_TEST_PROCESS_LIFETIME_HELPER=1"})
	})
	select {
	case <-stack.procs["restarted-control"].done:
		t.Fatal("shared control stopped when its initiating subtest finished")
	default:
	}
	t.Run("child-scoped", func(t *testing.T) {
		stack.start(t, "child-process", binary,
			[]string{"-test.run=^TestShippedProcessLifetimeHelper$"},
			[]string{"PROBECTL_TEST_PROCESS_LIFETIME_HELPER=1"})
	})
	select {
	case <-stack.procs["child-process"].done:
	default:
		t.Fatal("a child-scoped process escaped its test cleanup")
	}
}

func TestShippedProcessLifetimeHelper(_ *testing.T) {
	if os.Getenv("PROBECTL_TEST_PROCESS_LIFETIME_HELPER") != "1" {
		return
	}
	time.Sleep(time.Hour)
}
