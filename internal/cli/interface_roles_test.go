// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ctlplne/probectl/pkg/sdk"
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

func TestInterfaceRoleCompletePolicyReachesNamedRawCLIAndGeneratedSDK(t *testing.T) {
	definition := map[string]any{"provider_asns": []uint32{4294967295}, "customer_asns": []uint32{64501}}
	rules := []map[string]any{}
	for i := 0; i < 4097; i++ {
		rules = append(rules, map[string]any{"pattern": strings.Repeat("core-uplink-", 24) + fmt.Sprint(i), "role": "backbone"})
	}
	definition["description_rules"] = rules
	input := map[string]any{"expected_id": "owned-incarnation", "expected_revision": "9007199254740993", "definition": definition}
	raw, err := json.Marshal(input)
	if err != nil || len(raw) <= 1<<20 {
		t.Fatal("complete policy fixture lost its intended input population", err)
	}
	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		calls := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var seen struct {
				ExpectedID       string `json:"expected_id"`
				ExpectedRevision string `json:"expected_revision"`
				Definition       struct {
					ProviderASNs     []uint32         `json:"provider_asns"`
					DescriptionRules []map[string]any `json:"description_rules"`
				} `json:"definition"`
			}
			if r.Method != http.MethodPut || r.URL.Path != "/v1/entity-contexts/owned-context/interface-role-policy" || r.Header.Get("X-Probectl-Tenant") != tenant || json.NewDecoder(r.Body).Decode(&seen) != nil || seen.ExpectedRevision != "9007199254740993" || seen.ExpectedID != "owned-incarnation" || len(seen.Definition.DescriptionRules) != 4097 || len(seen.Definition.ProviderASNs) != 1 || seen.Definition.ProviderASNs[0] != 4294967295 {
				t.Error("complete policy was truncated or changed before the served route")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			for i, rule := range seen.Definition.DescriptionRules {
				if rule["pattern"] != rules[i]["pattern"] {
					t.Error("complete policy rule order or value changed")
				}
			}
			calls++
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"revision": "9007199254740994", "definition": definition})
		}))
		// The generated client uses the real verified test TLS transport.
		client := sdk.NewClient(server.URL, sdk.WithHTTPClient(server.Client()), sdk.WithTenant(tenant))
		var body sdk.InterfaceRolePolicyInput
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatal(err)
		}
		result, err := client.PutInterfaceRolePolicy(t.Context(), sdk.PutInterfaceRolePolicyRequest{ContextId: "owned-context", Body: &body})
		if err != nil || result.Revision != "9007199254740994" || len(result.Definition.DescriptionRules) != 4097 {
			t.Fatal("generated client lost complete policy", err)
		}
		server.Close()
		// CLI trust roots are exercised by its standing TLS tests; this focused
		// body-file proof uses the existing allowed loopback test transport.
		local := httptest.NewServer(server.Config.Handler)
		env := func(key string) string {
			if key == "PROBECTL_API_URL" {
				return local.URL
			}
			return ""
		}
		for _, command := range [][]string{{"interface-roles", "set-policy", "owned-context"}, {"api", "PUT", "/v1/entity-contexts/owned-context/interface-role-policy"}} {
			args := append([]string{"--tenant", tenant, "--json"}, command...)
			args = append(args, "--body-file", "-")
			var stdout, stderr bytes.Buffer
			code := RunWithStdin(args, env, bytes.NewReader(raw), &stdout, &stderr)
			if code != 0 || !strings.Contains(stdout.String(), "9007199254740994") {
				t.Fatal("complete policy was refused by a former CLI body cap", code, stderr.String())
			}
		}
		local.Close()
		if calls != 3 {
			t.Fatal("named/raw CLI or generated SDK never reached complete policy route", calls)
		}
	}
}
