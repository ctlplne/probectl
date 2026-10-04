// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cipolicy

import (
	"regexp"
	"strings"
	"testing"
)

// TestAuthIntegrationSuiteStaysCIRequired closes the "lock CI" half of AUTHZ-30:
// the auth/RBAC/ABAC behavior is covered by a large //go:build integration suite
// in internal/control (login, deactivated-user, ABAC, CSRF/Origin, SCIM, MCP,
// API tokens, …) that only runs against a real Postgres. That coverage is worth
// nothing if the job stops being a required merge gate, and the failure mode is
// SILENT — a dropped `needs:` entry or a gutted run line turns the suite into
// dead code without any single test going red. This asserts the `integration`
// job both RUNS the suite (make test-integration) and is a REQUIRED dependency
// of the verify-all umbrella.
//
// Fail-before: remove `- integration` from verify-all.needs, or the
// `make test-integration` run, and the matching assertion fires.
func TestAuthIntegrationSuiteStaysCIRequired(t *testing.T) {
	ci := readWorkflow(t, "ci.yml")

	// (1) the integration job runs the suite.
	intJob := jobBlock(t, ci, "integration")
	if !strings.Contains(intJob, "make test-integration") {
		t.Error("AUTHZ-30: the `integration` job must run `make test-integration` (the real-Postgres auth/RBAC/ABAC suite)")
	}

	// (2) verify-all REQUIRES the integration job (so a suite failure blocks merge).
	vaJob := jobBlock(t, ci, "verify-all")
	needs := vaJob
	if i := strings.Index(vaJob, "steps:"); i > 0 {
		needs = vaJob[:i] // the needs list precedes steps
	}
	if !regexp.MustCompile(`(?m)^\s*-\s*integration\s*$`).MatchString(needs) {
		t.Error("AUTHZ-30: verify-all must list `- integration` in needs, so the auth integration suite is a required merge gate")
	}
}
