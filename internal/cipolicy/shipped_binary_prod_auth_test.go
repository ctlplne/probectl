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

// TestShippedBinaryRefusesDevAuth pins the in-repo half of TQ-03. TQ-03's full
// acceptance — a verify-all CI job that starts the RELEASE IMAGE in production
// auth and drives two-tenant writes/reads over HTTPS, failing on cross-tenant
// visibility, with `grep -E 'tags devauth|AUTH_MODE=dev' test/e2e` returning
// nothing — is a dex + TLS + release-image build-out parked to D-28. What the
// repo can prove today, and must keep proving, is that the SHIPPED (untagged)
// binary cannot be run with the dev-auth bypass at all: the no-devauth-in-release
// job compiles the release binary, asserts the dev-auth symbol + literal are
// absent, proves the gate is non-vacuous against a devauth-tagged build, and
// behaviorally boots the release binary with PROBECTL_AUTH_MODE=dev and requires
// it to refuse. This gate keeps that proof from being dropped.
func TestShippedBinaryRefusesDevAuth(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")
	job := jobBlock(t, ci, "no-devauth-in-release")
	for _, want := range []string{
		"PROBECTL_AUTH_MODE=dev",        // the behavioral boot-refusal check
		"not compiled into this binary", // the exact refusal the shipped binary must emit
		"devAuthPrincipal",              // the symbol that must be ABSENT from the release binary
		"dev@probectl.local",            // the dev-principal literal that must be absent
		"go build -tags devauth",        // the non-vacuity self-test build
	} {
		if !strings.Contains(job, want) {
			t.Errorf("TQ-03: ci.yml no-devauth-in-release job must keep the shipped-binary production-auth proof %q; "+
				"without it nothing proves the binary as shipped refuses the dev-auth bypass", want)
		}
	}
}
