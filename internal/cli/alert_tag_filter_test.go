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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAlertTagFilterCLIPreservesCompletePredicatesAndBindingRevision(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	wide := strings.Repeat("🌐", 24000)
	for _, mode := range []struct{ operation, method string }{{"tag-filter", http.MethodGet}, {"tag-filter-set", http.MethodPut}, {"tag-filter-clear", http.MethodDelete}} {
		t.Run(mode.operation, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != mode.method || r.URL.Path != "/v1/alerts/"+id+"/tag-filter" || r.URL.RawQuery != "" {
					t.Error("alert tag CLI changed its exact route")
				}
				if r.Method == http.MethodDelete {
					w.WriteHeader(http.StatusNoContent)
					return
				}
				if r.Method == http.MethodPut {
					var input struct {
						Target string `json:"target_kind"`
						Filter struct {
							Conditions []struct {
								Field  string   `json:"field"`
								Op     string   `json:"op"`
								Values []string `json:"values"`
							} `json:"conditions"`
						} `json:"filter"`
					}
					if json.NewDecoder(r.Body).Decode(&input) != nil || input.Target != "test" || len(input.Filter.Conditions) != 1 || input.Filter.Conditions[0].Field != "tag.customer" || input.Filter.Conditions[0].Op != "eq" || len(input.Filter.Conditions[0].Values) != 1 || input.Filter.Conditions[0].Values[0] != wide {
						t.Error("CLI shortened or changed full metadata criteria")
					}
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{"rule_id": id, "has_tag_filter": true, "tag_filter": map[string]any{"version": 1, "target_kind": "test", "tag_revision": "9007199254740993", "as_of": "2026-11-03T00:00:00Z", "filter": map[string]any{"conditions": []any{map[string]any{"field": "tag.customer", "op": "eq", "values": []string{wide}}}}}}); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(srv.Close)
			args := []string{"--json", "alert", mode.operation, id}
			if mode.method == http.MethodPut {
				body := filepath.Join(t.TempDir(), "criteria.json")
				data, err := json.Marshal(map[string]any{"target_kind": "test", "filter": map[string]any{"conditions": []any{map[string]any{"field": "tag.customer", "op": "eq", "values": []string{wide}}}}})
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(body, data, 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--body-file", body)
			}
			stdout, stderr, code := run(t, srv, args...)
			if code != 0 {
				t.Fatalf("alert tag CLI failed: %d %s", code, stderr)
			}
			if mode.method != http.MethodDelete && (!strings.Contains(stdout, wide) || !strings.Contains(stdout, "9007199254740993")) {
				t.Fatal("CLI lost complete metadata values or exact binding revision")
			}
		})
	}
}
