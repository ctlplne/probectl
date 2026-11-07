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
)

// Request/response serialization only: the modeled HTTP peer does not grant
// routing ownership, current credentials or storage isolation.
func TestBGPRoutingBindingsNamedAndRawCLIKeepWholeTenantConfiguration(t *testing.T) {
	bindings := make([]map[string]any, 8193)
	for i := range bindings {
		bindings[i] = map[string]any{"context_id": "11111111-1111-4111-8111-111111111111", "router_id": "22222222-2222-4222-8222-222222222222", "distinguisher": "0000000000000000", "bgp_identifier": fmt.Sprintf("192.0.%d.%d", i/256, i%256), "families": []int{1, 2}, "source_format": "frr_loc_rib_v1"}
	}
	complete, err := json.Marshal(map[string]any{"collector_agent_id": "owned-collector", "source_ref": "owned-origin", "expected_epoch": "9007199254740993", "bindings": bindings})
	if err != nil || len(complete) <= 1<<20 {
		t.Fatal("complete CLI fixture lost former body ceiling", err)
	}
	empty := []byte(`{"collector_agent_id":"owned-collector","source_ref":"owned-origin","expected_epoch":"9007199254740993","bindings":[]}`)
	const path = "/v1/entity-contexts/11111111-1111-4111-8111-111111111111/bgp-routing-bindings"
	for _, tenant := range []string{"11111111-1111-4111-8111-111111111111", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"} {
		var want []byte
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.URL.Path != path || r.Header.Get("X-Probectl-Tenant") != tenant {
				t.Error("routing CLI changed tenant or context")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.Method == http.MethodGet {
				if r.URL.Query().Get("collector_agent_id") != "owned-collector" || r.URL.Query().Get("source_ref") != "owned-origin" {
					t.Error("routing CLI lost origin selector")
				}
			} else if r.Method == http.MethodPut {
				got, e := io.ReadAll(r.Body)
				var actual, expected any
				if e != nil || json.Unmarshal(got, &actual) != nil || json.Unmarshal(want, &expected) != nil {
					t.Error("routing CLI refused complete body")
					return
				}
				a, _ := json.Marshal(actual)
				b, _ := json.Marshal(expected)
				if !bytes.Equal(a, b) {
					t.Error("routing CLI changed complete replacement, epoch or withdrawal")
				}
			} else {
				t.Error("routing CLI changed method")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"epoch":"9007199254740993","opaque_counter":9007199254740993}`)
		}))
		env := func(key string) string {
			if key == "PROBECTL_API_URL" {
				return server.URL
			}
			return ""
		}
		for _, named := range []bool{true, false} {
			command := []string{"api", "GET", path}
			if named {
				command = []string{"routing-bindings", "read", "11111111-1111-4111-8111-111111111111"}
			}
			args := append([]string{"--tenant", tenant, "--json"}, command...)
			args = append(args, "--query", "collector_agent_id=owned-collector", "--query", "source_ref=owned-origin")
			var stdout, stderr bytes.Buffer
			if code := RunWithStdin(args, env, strings.NewReader(""), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), `"opaque_counter": 9007199254740993`) {
				t.Fatal("routing CLI lost exact read identity", code, stdout.String(), stderr.String())
			}
			for _, body := range [][]byte{complete, empty} {
				want = body
				command = []string{"api", "PUT", path}
				if named {
					command = []string{"routing-bindings", "replace", "11111111-1111-4111-8111-111111111111"}
				}
				args = append([]string{"--tenant", tenant, "--json"}, command...)
				args = append(args, "--body-file", "-")
				stdout.Reset()
				stderr.Reset()
				if code := RunWithStdin(args, env, bytes.NewReader(body), &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "9007199254740993") {
					t.Fatal("routing CLI refused complete replacement", code, stderr.String())
				}
			}
		}
		server.Close()
		if calls != 6 {
			t.Fatal("routing CLI operation never reached modeled peer", calls)
		}
	}
}
