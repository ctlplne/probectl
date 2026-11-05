// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestInterfaceRoleCLIUsesOwnedRoutesAndExactDecimalRevision(t *testing.T) {
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		for _, test := range []struct {
			operation, method, suffix string
			subject, body             bool
		}{
			{"policy", http.MethodGet, "interface-role-policy", false, false},
			{"set-policy", http.MethodPut, "interface-role-policy", false, true},
			{"override", http.MethodGet, "interfaces/owned-interface/role-override", true, false},
			{"set-override", http.MethodPut, "interfaces/owned-interface/role-override", true, true},
			{"reset-override", http.MethodDelete, "interfaces/owned-interface/role-override", true, true},
		} {
			t.Run(tenant+"/"+test.operation, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != test.method || r.URL.Path != "/v1/entity-contexts/owned-context/"+test.suffix || r.Header.Get("X-Probectl-Tenant") != tenant {
						t.Error("CLI role operation changed owned route or tenant")
					}
					if test.body {
						var body map[string]any
						if json.NewDecoder(r.Body).Decode(&body) != nil || body["expected_revision"] != "9007199254740993" || body["expected_id"] != "owned-incarnation" {
							t.Error("CLI role operation changed exact CAS identity")
						}
					}
					if test.method == http.MethodDelete {
						w.WriteHeader(http.StatusNoContent)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = io.WriteString(w, `{"revision":"9007199254740993"}`)
				}))
				defer server.Close()
				args := []string{"--tenant", tenant, "--json", "interface-roles", test.operation, "owned-context"}
				if test.subject {
					args = append(args, "owned-interface")
				}
				if test.body {
					args = append(args, "--body", `{"expected_id":"owned-incarnation","expected_revision":"9007199254740993","confirmed":true}`)
				}
				stdout, stderr, code := run(t, server, args...)
				if code != 0 || (test.method != http.MethodDelete && !strings.Contains(stdout, "9007199254740993")) {
					t.Fatalf("native role CLI failed: %d %s %s", code, stdout, stderr)
				}
			})
		}
	}
}
