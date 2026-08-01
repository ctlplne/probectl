// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package docs

import (
	"os"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/internal/govern"
)

func TestGovernanceDocsListEveryCoreCategory(t *testing.T) {
	b, err := os.ReadFile("governance.md")
	if err != nil {
		t.Fatalf("read governance.md: %v", err)
	}
	doc := string(b)
	for _, cat := range govern.Categories() {
		if !strings.Contains(doc, "`"+string(cat)+"`") {
			t.Fatalf("governance.md does not document core governance category %q", cat)
		}
	}
}
