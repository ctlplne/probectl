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

func TestSavedQueryAlertCLIUsesExactSourceOperations(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	const input = `{"view_id":"22222222-2222-4222-8222-222222222222","view_version":"9007199254740993","condition":{"mode":"threshold","metric":"bytes:total","comparison":"gt","threshold":"18446744073709551617"}}`
	for _, op := range []struct{ name, method string }{{"query-source", http.MethodGet}, {"query-source-set", http.MethodPut}, {"query-source-clear", http.MethodDelete}} {
		t.Run(op.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/v1/alerts" && r.Method == http.MethodGet {
					_, _ = w.Write([]byte(`{"alerting_active":true}`))
					return
				}
				calls++
				if r.Method != op.method || r.URL.Path != "/v1/alerts/rules/"+id+"/query-source" {
					t.Error("CLI changed source operation", r.Method, r.URL.Path)
				}
				if r.Method == http.MethodPut {
					var body json.RawMessage
					if json.NewDecoder(r.Body).Decode(&body) != nil || !strings.Contains(string(body), `"threshold":"18446744073709551617"`) || !strings.Contains(string(body), `"view_version":"9007199254740993"`) {
						t.Error("CLI rounded condition or source revision")
					}
				}
				if r.Method == http.MethodDelete {
					_, _ = w.Write([]byte(`{"configured":false}`))
					return
				}
				_, _ = w.Write([]byte(`{"configured":true,"source":` + input + `}`))
			}))
			t.Cleanup(server.Close)
			args := []string{"--json", "alert", op.name, id}
			if op.method == http.MethodPut {
				args = append(args, "--body", input)
			}
			stdout, stderr, code := run(t, server, args...)
			if code != 0 || calls != 1 {
				t.Fatal("source CLI failed", code, stderr, calls)
			}
			if op.method != http.MethodDelete && (!strings.Contains(stdout, "18446744073709551617") || !strings.Contains(stdout, "9007199254740993")) {
				t.Fatal("CLI rounded complete source output", stdout)
			}
		})
	}
}
