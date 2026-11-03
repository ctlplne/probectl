// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEffectiveTagsCLIRoutesAllOwnedSubjectReferencesAndKeepsExactRevision(t *testing.T) {
	for _, kind := range []string{"device", "interface", "prefix", "agent", "test", "exporter"} {
		t.Run(kind, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/entity-contexts/owned-context/resolved-tags" || r.URL.Query().Get("target_kind") != kind {
					t.Errorf("unexpected subject request: %s %s", r.Method, r.URL.RequestURI())
				}
				if kind == "exporter" {
					if r.URL.Query().Get("exporter_agent_id") != "registered-agent" || r.URL.Query().Get("exporter_source_ref") != "192.0.2.9" || r.URL.Query().Get("target_id") != "" {
						t.Error("exporter tuple changed")
					}
				} else if r.URL.Query().Get("target_id") != "owned-subject" {
					t.Error("canonical reference changed")
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"context_id":"owned-context","target_kind":"` + kind + `","tag_revision":"9007199254740993","as_of":"2026-11-03T00:00:00Z","items":[{"tag_id":"tag","key":"customer","value":"gold","source":"manual"}]}`))
			}))
			t.Cleanup(srv.Close)
			args := []string{"--json", "tags", "resolve", "owned-context", "--query", "target_kind=" + kind}
			if kind == "exporter" {
				args = append(args, "--query", "exporter_agent_id=registered-agent", "--query", "exporter_source_ref=192.0.2.9")
			} else {
				args = append(args, "--query", "target_id=owned-subject")
			}
			stdout, stderr, code := run(t, srv, args...)
			if code != 0 || !strings.Contains(stdout, "9007199254740993") || !strings.Contains(stdout, "gold") {
				t.Fatalf("subject CLI: exit=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
		})
	}
}
