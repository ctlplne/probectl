// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package completeness

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestExportedRootsKeepCheckoutIsolationAndDoNotCacheParseFailure(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "entry.go")
	write := func(source string) {
		t.Helper()
		if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("package example\nfunc First() {}\nfunc hidden() {}\n")
	v := &Validator{root: root}
	got, err := v.exportedPackageRoots(".")
	if err != nil || !slices.Equal(got, []string{"First"}) {
		t.Fatal("exported dispatch root changed", got, err)
	}
	got[0] = "forged"
	again, err := v.exportedPackageRoots(".")
	if err != nil || !slices.Equal(again, []string{"First"}) {
		t.Fatal("caller mutated cached dispatch roots", again, err)
	}
	write("package example\nfunc Broken(\n")
	fresh := &Validator{root: root}
	if roots, err := fresh.exportedPackageRoots("."); err == nil || roots != nil {
		t.Fatal("new checkout validator reused stale roots over malformed source")
	}
	write("package example\nfunc Second() {}\n")
	got, err = fresh.exportedPackageRoots(".")
	if err != nil || !slices.Equal(got, []string{"Second"}) {
		t.Fatal("parse failure was cached or another validator supplied roots", got, err)
	}
	if roots, err := fresh.exportedPackageRoots("../"); err == nil || roots != nil {
		t.Fatal("cached roots bypassed repository containment")
	}
}
