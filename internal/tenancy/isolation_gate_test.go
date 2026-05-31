//go:build isolation

// Cross-tenant isolation gate — a permanent CI gate, seeded in S0.
//
// CLAUDE.md §7 guardrail 1: cross-tenant data leakage is the highest-severity
// failure class. A cross-tenant isolation test must accompany every change to a
// data-access path, and CI runs a dedicated cross-tenant isolation suite.
//
// S0 scaffold: this is an intentional placeholder so the `cross-tenant-isolation`
// CI job and the `make test-isolation` target exist and stay green from day one.
// S2 replaces the body below with the real suite, asserting that a repository
// call made in tenant A's context can never return tenant B's rows (F50/F52).
package tenancy_test

import "testing"

// TestCrossTenantIsolationPlaceholder is replaced by the real isolation suite in
// S2. It passes today so the permanent gate is wired end-to-end.
func TestCrossTenantIsolationPlaceholder(t *testing.T) {
	t.Log("cross-tenant isolation gate placeholder — real suite lands in S2 (F50/F52)")
}
