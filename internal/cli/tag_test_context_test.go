// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTestTagContextCLIPreservesExactReferencesValuesAndRevision(t *testing.T) {
	value := strings.Repeat("🌐", 24000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			IDs []string `json:"test_ids"`
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tags/tests/resolve" || r.URL.RawQuery != "" || json.NewDecoder(r.Body).Decode(&input) != nil || len(input.IDs) != 2 || input.IDs[0] != "test-a" || input.IDs[1] != "test-b" {
			t.Error("test context CLI changed the exact body references or route")
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{"tag_revision": "9007199254740993", "as_of": "2026-11-03T00:00:00Z", "items": []any{map[string]any{"target_kind": "test", "target_id": "test-a", "context_id": "context", "tag_revision": "9007199254740993", "as_of": "2026-11-03T00:00:00Z", "items": []any{map[string]string{"tag_id": "customer", "key": "customer", "value": value, "source": "rule"}}}}}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	stdout, stderr, code := run(t, srv, "--json", "tags", "tests", "--body", `{"test_ids":["test-a","test-b"]}`)
	if code != 0 || !strings.Contains(stdout, "9007199254740993") || !strings.Contains(stdout, value) {
		t.Fatalf("test context CLI lost the exact revision or full value: exit=%d stderr=%s", code, stderr)
	}
}
