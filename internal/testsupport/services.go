// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package testsupport holds shared test-only helpers. It imports testing so it
// is only ever linked into test binaries.
package testsupport

import (
	"os"
	"testing"
)

// RequireServices reports whether the suite must FAIL (not skip) when a backing
// service is unavailable. CI sets PROBECTL_TEST_REQUIRE_SERVICES=1 for the
// isolation and safety suites (TEST-003/004): there, a missing Postgres /
// ClickHouse is a RED build, not a silent skip — a cross-tenant isolation test
// that quietly skips is the exact "vacuous green" the audit flagged. Locally
// (unset) the suites still skip cleanly so a laptop without the stack works.
func RequireServices() bool {
	return os.Getenv("PROBECTL_TEST_REQUIRE_SERVICES") == "1"
}

// SkipOrFatal skips the test when services are optional (local dev) but FAILS
// it when PROBECTL_TEST_REQUIRE_SERVICES=1 (CI) — so a safety/isolation suite
// can never pass by skipping in the environment that is supposed to enforce it.
func SkipOrFatal(t testing.TB, format string, args ...any) {
	t.Helper()
	if RequireServices() {
		t.Fatalf("PROBECTL_TEST_REQUIRE_SERVICES=1 but a required service is unavailable: "+format, args...)
	}
	t.Skipf(format, args...)
}
