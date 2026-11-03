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

func TestNetBoxImportCLIRoutesAllOwnedKindsAndExactSourceIdentifiers(t *testing.T) {
	for _, kind := range []string{"exporter", "device", "interface", "prefix", "agent", "test"} {
		t.Run(kind, func(t *testing.T) {
			input := map[string]any{"tag_id": "00000000-0000-4000-8000-000000000001", "target_kind": kind, "field": "role", "source_id": "9007199254740993"}
			if kind == "exporter" {
				input["exporter_agent_id"], input["exporter_source_ref"] = "registered-agent", "192.0.2.10"
			} else {
				input["target_id"] = "00000000-0000-4000-8000-000000000002"
			}
			for _, operation := range []string{"netbox-preview", "netbox-apply"} {
				body := input
				if operation == "netbox-apply" {
					body = map[string]any{"confirmed": true, "preview": map[string]any{"target": input, "candidate": map[string]any{"lookup_ci_id": "netbox:ipam.prefix:9007199254740993", "source_ref": "reviewed-reference"}}}
				}
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					path := "preview"
					if operation == "netbox-apply" {
						path = "apply"
					}
					if r.Method != http.MethodPost || r.URL.Path != "/v1/entity-contexts/owned-context/tag-imports/netbox/"+path {
						t.Error("CLI changed the native import route")
					}
					var seen map[string]any
					if err := json.NewDecoder(r.Body).Decode(&seen); err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					projection := seen
					if operation == "netbox-apply" {
						if seen["confirmed"] != true {
							t.Error("CLI dropped explicit confirmation")
						}
						projection = seen["preview"].(map[string]any)["target"].(map[string]any)
					}
					if projection["source_id"] != "9007199254740993" || projection["target_kind"] != kind {
						t.Error("CLI changed subject or decimal source identity")
					}
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"tag_revision":"9007199254740993","value":"imported"}`))
				}))
				stdout, stderr, code := run(t, server, "--json", "tags", operation, "owned-context", "--body", string(raw))
				server.Close()
				if code != 0 || !strings.Contains(stdout, "9007199254740993") {
					t.Fatalf("native CLI import %s: %d %s %s", operation, code, stdout, stderr)
				}
			}
		})
	}
}
