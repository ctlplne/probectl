// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package main

import (
	"os"
	"os/exec"
	"testing"
)

// requireOrSkipHelm gates the Helm-render tests on the `helm` binary (TQ-13).
// When PROBECTL_TEST_REQUIRE_HELM=1 (set in the helm-provisioned CI lane) a
// missing helm is a hard FAILURE, so these tests can never silently skip in the
// lane meant to run them; locally (flag unset) they still skip gracefully.
func requireOrSkipHelm(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("helm"); err == nil {
		return
	}
	if os.Getenv("PROBECTL_TEST_REQUIRE_HELM") == "1" {
		t.Fatal("helm is not installed, but PROBECTL_TEST_REQUIRE_HELM=1 requires the Helm render tests to run")
	}
	t.Skip("helm is not installed (set PROBECTL_TEST_REQUIRE_HELM=1 to require)")
}
