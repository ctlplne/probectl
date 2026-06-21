// SPDX-License-Identifier: LicenseRef-probectl-TBD

package docs

import (
	"os"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/govern"
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
