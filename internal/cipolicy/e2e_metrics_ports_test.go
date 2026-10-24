// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestE2EProcessesGetTheirOwnMetricsPort pins DPR-321: every collector binary
// listens for metrics on a fixed default port unless PREFIX_METRICS_ADDR says
// otherwise, and the black-box e2e runs two eBPF agents (and several canaries)
// on one runner. Tenant B's agent lost the bind race, exited before its first
// flush, and the e2e timed out on its topology edge (CI run 40103763025). The
// e2e's startProc must hand every collector it could start a kernel-picked
// loopback port, for each prefix a cmd/*/main.go reads.
func TestE2EProcessesGetTheirOwnMetricsPort(t *testing.T) {
	root := repoRoot(t)
	mains, err := filepath.Glob(filepath.Join(root, "cmd", "*", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	prefix := regexp.MustCompile(`agentmetrics\.ConfigFromEnv\(os\.Getenv, "([A-Z_]+)"`)
	var prefixes []string
	for _, m := range mains {
		raw, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		for _, sub := range prefix.FindAllStringSubmatch(string(raw), -1) {
			prefixes = append(prefixes, sub[1])
		}
	}
	if len(prefixes) < 6 {
		t.Fatalf("found %d collector metrics prefixes in cmd/*/main.go (%v), want all six", len(prefixes), prefixes)
	}
	raw, err := os.ReadFile(filepath.Join(root, "test", "e2e", "e2e_test.go"))
	if err != nil {
		t.Fatal(err)
	}
	e2e := string(raw)
	if !strings.Contains(e2e, "cmd.Env = append(append(os.Environ(), ownMetricsAddr...), env...)") {
		t.Error("DPR-321: test/e2e startProc must start every process with ownMetricsAddr")
	}
	for _, p := range prefixes {
		if want := `"` + p + `_METRICS_ADDR=127.0.0.1:0"`; !strings.Contains(e2e, want) {
			t.Errorf("DPR-321: test/e2e ownMetricsAddr must give %s its own port (%s missing)", p, want)
		}
	}
}
