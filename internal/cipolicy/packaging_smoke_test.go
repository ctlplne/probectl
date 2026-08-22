// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cipolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagingSmokeUsesPortableSed(t *testing.T) {
	t.Parallel()

	scriptPath := filepath.Join("..", "..", "scripts", "packaging-smoke.sh")
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	if strings.Contains(script, "\nsed -i ") {
		t.Fatal("packaging smoke uses non-portable in-place sed")
	}
	for _, required := range []string{
		`absolute_rendered="$work/nfpm.absolute.yaml"`,
		`> "$absolute_rendered"`,
		`mv "$absolute_rendered" "$rendered"`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("packaging smoke is missing portable render contract %q", required)
		}
	}
}
