// SPDX-License-Identifier: LicenseRef-probectl-TBD

package testsupport

import "testing"

// fakeTB records whether Skip or Fatal was called (the two terminal outcomes).
type fakeTB struct {
	testing.TB
	skipped bool
	fatal   bool
}

func (f *fakeTB) Helper()               {}
func (f *fakeTB) Skipf(string, ...any)  { f.skipped = true; panic("skip") }
func (f *fakeTB) Fatalf(string, ...any) { f.fatal = true; panic("fatal") }

func runCatching(fn func()) {
	defer func() { _ = recover() }()
	fn()
}

// TEST-003: SkipOrFatal must SKIP when services are optional and FAIL when
// PROBECTL_TEST_REQUIRE_SERVICES=1, so a CI isolation suite can't pass by
// skipping.
func TestSkipOrFatalRespectsRequireServices(t *testing.T) {
	t.Setenv("PROBECTL_TEST_REQUIRE_SERVICES", "")
	f := &fakeTB{}
	runCatching(func() { SkipOrFatal(f, "no db") })
	if !f.skipped || f.fatal {
		t.Fatalf("optional mode: want skip, got skipped=%v fatal=%v", f.skipped, f.fatal)
	}

	t.Setenv("PROBECTL_TEST_REQUIRE_SERVICES", "1")
	f2 := &fakeTB{}
	runCatching(func() { SkipOrFatal(f2, "no db") })
	if !f2.fatal || f2.skipped {
		t.Fatalf("required mode: want fatal, got skipped=%v fatal=%v", f2.skipped, f2.fatal)
	}
}
