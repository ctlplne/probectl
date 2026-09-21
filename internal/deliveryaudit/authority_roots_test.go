// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package deliveryaudit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A review protocol accepts evidence only from inside its declared roots, so a
// root naming a directory that does not exist accepts NOTHING: the item can never
// be satisfied, and the protocol reads as coverage while auditing nothing.
//
// Four of the five review protocols were in that state — bound to a retired
// program's layout (evidence/, docs/product/, docs/competitive/, docs/release/) —
// and no gate noticed, because a dead root fails by silently matching nothing
// rather than by erroring.
func TestReviewProtocolRootsExist(t *testing.T) {
	t.Parallel()
	const authority = "../../docs/contract/delivery-audit-review-protocols.json"
	raw, err := os.ReadFile(authority)
	if err != nil {
		t.Fatalf("read %s: %v", authority, err)
	}
	var doc struct {
		ReviewProtocols []struct {
			Item             string   `json:"item"`
			MethodologyRoots []string `json:"methodology_roots"`
			SubjectRoots     []string `json:"subject_roots"`
		} `json:"review_protocols"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse %s: %v", authority, err)
	}
	if len(doc.ReviewProtocols) == 0 {
		t.Fatalf("%s declares no review protocols — the parse broke, so this test proves nothing", authority)
	}
	repoRoot := filepath.Join("..", "..")
	for _, proto := range doc.ReviewProtocols {
		for label, roots := range map[string][]string{
			"methodology_roots": proto.MethodologyRoots,
			"subject_roots":     proto.SubjectRoots,
		} {
			if len(roots) == 0 {
				t.Errorf("%s %s is empty, so no evidence can ever satisfy it", proto.Item, label)
				continue
			}
			for _, root := range roots {
				clean := strings.TrimSuffix(root, "/")
				if clean == "" || strings.Contains(clean, "..") {
					t.Errorf("%s %s contains an unusable root %q", proto.Item, label, root)
					continue
				}
				info, err := os.Stat(filepath.Join(repoRoot, clean))
				if err != nil || !info.IsDir() {
					t.Errorf("%s %s names %q, which is not a directory in this repository — the protocol accepts no evidence at all", proto.Item, label, root)
				}
			}
		}
	}
}
