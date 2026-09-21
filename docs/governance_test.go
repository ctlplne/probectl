// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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
