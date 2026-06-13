// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package testsupport holds shared test-only helpers. It imports testing so it
// is only ever linked into test binaries.
package testsupport

import (
	"os"
	"strings"
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

// PostgresDSN resolves the test Postgres DSN from the environment, in
// precedence order (TEST-003):
//
//	PROBECTL_DATABASE_URL   — what the CI integration job exports (ci_pg_tls.sh)
//	PROBECTL_TEST_POSTGRES  — the legacy per-suite override (kept for back-compat)
//	localhost fallback      — a plaintext dev DSN for a local docker-compose PG
//
// Suites previously each read PROBECTL_TEST_POSTGRES (which CI never set) and
// fell back to localhost, so they silently skipped even in the require-services
// job. Unifying on this resolver means the same DSN the integration job exports
// is what every integration suite connects to.
func PostgresDSN() string {
	if v := os.Getenv("PROBECTL_DATABASE_URL"); v != "" {
		return v
	}
	if v := os.Getenv("PROBECTL_TEST_POSTGRES"); v != "" {
		return v
	}
	return "postgres://probectl:probectl@localhost:5432/probectl"
}

// KafkaBrokers resolves the test Kafka bootstrap brokers from the environment.
// PROBECTL_TEST_KAFKA is what the full-stack CI jobs export (e.g.
// "localhost:9092"); it is comma-separated for a multi-broker cluster. An empty
// result means no bus is configured — a caller pairs this with SkipOrFatal so
// the suite fails (not skips) under PROBECTL_TEST_REQUIRE_SERVICES=1 and skips
// cleanly on a laptop without a broker.
func KafkaBrokers() []string {
	v := os.Getenv("PROBECTL_TEST_KAFKA")
	if v == "" {
		return nil
	}
	var out []string
	for _, b := range strings.Split(v, ",") {
		if b = strings.TrimSpace(b); b != "" {
			out = append(out, b)
		}
	}
	return out
}
