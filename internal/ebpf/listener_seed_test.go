// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// TestJudgeListenerSeedIsTruthful is the ING-24 contract for the start-time
// seed report: only an iterator that ran AND was handed files counts as
// seeded. The old report said "seeded" for a walk that read to EOF having
// seen nothing.
func TestJudgeListenerSeedIsTruthful(t *testing.T) {
	cases := []struct {
		name       string
		loaded     bool
		err        error
		stats      [4]uint64
		attributed bool
		reason     string
	}{
		{"iterator saw listeners", true, nil, [4]uint64{6861, 912, 146, 71}, true, ""},
		{"no listener predates the agent", true, nil, [4]uint64{35, 1, 0, 0}, true, ""},
		{"walk read to the end but saw no file", true, nil, [4]uint64{}, false, "never handed an open file"},
		{"iterator refused at attach", true, errors.New("attach: permission denied"), [4]uint64{}, false, "permission denied"},
		{"kernel without bpf_sock_from_file", false, nil, [4]uint64{}, false, ">= 5.11"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := judgeListenerSeed(c.loaded, c.err, c.stats)
			if s.Attributed() != c.attributed {
				t.Fatalf("attributed = %t, want %t (%+v)", s.Attributed(), c.attributed, s)
			}
			if s.stats() != c.stats {
				t.Errorf("stats %v, want %v", s.stats(), c.stats)
			}
			if c.attributed {
				if s.Method != ListenerSeedTaskFileIterator || s.Reason != "" {
					t.Errorf("seeded report %+v, want the iterator method and no reason", s)
				}
				return
			}
			if s.Method != ListenerSeedNone || !strings.Contains(s.Reason, c.reason) {
				t.Errorf("report %+v, want method %q and a reason containing %q", s, ListenerSeedNone, c.reason)
			}
		})
	}
}

type seedReporter struct {
	Source
	seed ListenerSeed
}

func (r seedReporter) ListenerSeedReport() ListenerSeed { return r.seed }

// TestStartupLogNamesHowListenersWereSeeded: the agent's start log says which
// way pre-existing listeners were seeded, and when they were not, says so at
// WARN with the reason.
func TestStartupLogNamesHowListenersWereSeeded(t *testing.T) {
	for _, c := range []struct {
		seed ListenerSeed
		want []string
	}{
		{judgeListenerSeed(true, nil, [4]uint64{10, 2, 1, 1}), []string{"level=INFO", `method="bpf task_file iterator"`, "preexisting_listeners_attributed=true", "owners_recorded=1"}},
		{judgeListenerSeed(true, nil, [4]uint64{}), []string{"level=WARN", "NOT seeded", "method=none", "preexisting_listeners_attributed=false", "never handed an open file"}},
	} {
		var buf bytes.Buffer
		logListenerSeed(slog.New(slog.NewTextHandler(&buf, nil)), seedReporter{seed: c.seed})
		for _, w := range c.want {
			if !strings.Contains(buf.String(), w) {
				t.Errorf("startup log %q lacks %q", buf.String(), w)
			}
		}
	}
}
