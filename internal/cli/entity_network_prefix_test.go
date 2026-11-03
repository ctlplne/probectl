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

func TestPrefixNetworkCLIPreservesIDContextAndExplicitClear(t *testing.T) {
	for _, network := range []string{"2001:db8::/32", ""} {
		t.Run(network, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var body map[string]string
				if r.Method != http.MethodPut || r.URL.Path != "/v1/entities/stable-prefix/network-prefix" || json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["context_id"] != "owned-context" || body["network_prefix"] != network {
					t.Error("CLI changed the owned prefix request")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"id": "stable-prefix", "network_prefix": network})
			}))
			t.Cleanup(srv.Close)
			body, err := json.Marshal(map[string]string{"context_id": "owned-context", "network_prefix": network})
			if err != nil {
				t.Fatal(err)
			}
			out, stderr, code := run(t, srv, "--json", "entities", "network-set", "stable-prefix", "--body", string(body))
			if code != 0 || calls != 1 || !strings.Contains(out, "stable-prefix") {
				t.Fatalf("CLI prefix update code%d out%s err%s", code, out, stderr)
			}
		})
	}
}
