// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"strings"
	"testing"
)

// TestLintCompilesIntegrationTaggedTests (DPR-097): the UDP chaos self-test
// (internal/chaos, `-tags integration`) is the journey's documented evidence
// that the burn alert fires under fault and clears on heal, yet nothing built
// it in CI — it stopped compiling when two SLO signatures changed and nobody
// noticed. `make lint-go` now vets every module with the integration tag so
// integration tests cannot rot silently, whatever the CI database matrix runs.
func TestLintCompilesIntegrationTaggedTests(t *testing.T) {
	mk := readRepoFile(t, "Makefile")
	start := strings.Index(mk, "\nlint-go:")
	if start < 0 {
		t.Fatal("Makefile has no lint-go target")
	}
	lintGo := mk[start:]
	if end := strings.Index(lintGo[1:], "\n\n"); end > 0 {
		lintGo = lintGo[:end+1]
	}
	if !strings.Contains(lintGo, "vet -tags integration ./...") {
		t.Fatal("Makefile lint-go must run `go vet -tags integration ./...` so integration-tagged tests keep compiling")
	}
	ci := readWorkflow(t, "ci.yml")
	if !strings.Contains(ci, "run: make lint-go") {
		t.Fatal("ci.yml must run make lint-go (which vets the integration-tagged tests)")
	}
}
