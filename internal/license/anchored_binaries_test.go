// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package license

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// DPR-024: the image build asserts the link-time trust anchor only for the
// binaries that verify license files. That list must equal the set of cmd/
// packages that import this package directly: a new verifier that is not
// listed would ship without the assertion, and a listed non-verifier would
// fail every keyed image build (the linker drops the unused anchor string).
func TestAnchoredBinariesListMatchesDirectImporters(t *testing.T) {
	raw, err := os.ReadFile("anchored_binaries.txt")
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		listed[line] = true
	}
	if !listed["probectl-control"] {
		t.Fatal("anchored_binaries.txt must list probectl-control, the binary that loads license files")
	}
	importers := map[string]bool{}
	dirs, err := filepath.Glob(filepath.Join("..", "..", "cmd", "*", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range dirs {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(src), `"github.com/ctlplne/probectl/internal/license"`) {
			importers[filepath.Base(filepath.Dir(f))] = true
		}
	}
	var missing, extra []string
	for c := range importers {
		if !listed[c] {
			missing = append(missing, c)
		}
	}
	for c := range listed {
		if !importers[c] {
			extra = append(extra, c)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("cmd packages that import internal/license but are not in anchored_binaries.txt: %v", missing)
	}
	if len(extra) > 0 {
		t.Errorf("anchored_binaries.txt lists binaries that do not import internal/license directly: %v", extra)
	}
}
