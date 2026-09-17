// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
	lintGo := mk[strings.Index(mk, "\nlint-go:"):]
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
