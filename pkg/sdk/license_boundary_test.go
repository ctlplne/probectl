// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package sdk_test

import (
	"os/exec"
	"strings"
	"testing"
)

// TestPkgTreeImportsNoBUSLCore is the PLAT-12 license-boundary gate: the
// MPL-2.0 client tree (pkg/) must not compile in any BUSL-1.1 core
// (internal/*) or commercial (ee/*) package, or the SDK could not be
// distributed under the MPL. It asserts the production (non-test) dependency
// closure is clean; a regression (e.g. the generator emitting an internal/
// import again) fails here.
func TestPkgTreeImportsNoBUSLCore(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/ctlplne/probectl/pkg/...").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ./pkg/...: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		dep := strings.TrimSpace(line)
		if strings.HasPrefix(dep, "github.com/ctlplne/probectl/internal/") ||
			strings.HasPrefix(dep, "github.com/ctlplne/probectl/ee/") {
			t.Errorf("PLAT-12: pkg/ depends on the BUSL/commercial package %q — the MPL-2.0 SDK must import no internal/ or ee/ package", dep)
		}
	}
}
