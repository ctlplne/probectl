// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package docs

import (
	"os"
	"strings"
	"testing"
)

func TestAgentOverheadRunbookDocumentsLivePrerequisites(t *testing.T) {
	b, err := os.ReadFile("agent-overhead.md")
	if err != nil {
		t.Fatalf("read agent-overhead.md: %v", err)
	}
	doc := string(b)

	for _, want := range []string{
		"make ebpf-agent",
		"generates vmlinux.h, bpf2go bindings, and object digests",
		"PROBECTL_OVERHEAD_SECONDS=60 go test -tags ebpf",
		"OVERHEAD ROW",
		"Rows from Docker Desktop, CI-scale build checks, or a run that skipped",
		"Only paste a row from a supported Linux host running the defined traffic mix",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("agent-overhead.md missing live-overhead prerequisite %q", want)
		}
	}
}
