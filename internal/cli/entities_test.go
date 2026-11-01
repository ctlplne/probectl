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
	"testing"
)

func TestEntityCLIUsesScopedReadRoutes(t *testing.T) {
	const (
		contextID = "00000000-0000-4000-8000-000000000101"
		entityID  = "00000000-0000-4000-8000-000000000102"
	)
	seen := make(chan string, 3)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": entityID})
	}))
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"entities", "list", "--query", "context_id=" + contextID,
			"--query", "limit=25"},
			"GET /v1/entities?context_id=" + contextID + "&limit=25"},
		{[]string{"entities", "get", entityID, "--query", "context_id=" + contextID},
			"GET /v1/entities/" + entityID + "?context_id=" + contextID},
		{[]string{"entities", "resolve", "--query", "context_id=" + contextID,
			"--query", "kind=address", "--query", "value=10.42.0.1"},
			"GET /v1/entities/resolve?context_id=" + contextID + "&kind=address&value=10.42.0.1"},
		{[]string{"entities", "path-resolve", entityID},
			"GET /v1/tests/" + entityID + "/path/entities"},
	} {
		out, errs, code := run(t, srv, tc.args...)
		if code != 0 {
			t.Fatalf("%v exit=%d stderr=%s stdout=%s", tc.args, code, errs, out)
		}
		if got := <-seen; got != tc.want {
			t.Fatalf("%v routed %q, want %q", tc.args, got, tc.want)
		}
	}
}

func TestEntityCLIUsesAdministrativeRoutes(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000101"
	seen := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"id": id})
	}))
	t.Cleanup(srv.Close)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"entities", "contexts", "list", "--query", "limit=25"},
			"GET /v1/entity-contexts?limit=25"},
		{[]string{"entities", "contexts", "create", "--body", `{"site_label":"West DC","vrf_label":"Customer A"}`},
			"POST /v1/entity-contexts"},
		{[]string{"entities", "create", "--body", `{"context_id":"` + id + `","kind":"device","label":"router"}`},
			"POST /v1/entities"},
		{[]string{"entities", "sources", "assign", "--body", `{"agent_id":"` + id + `","source_kind":"device_target","source_ref":"r1","context_id":"` + id + `"}`},
			"PUT /v1/entity-source-contexts"},
		{[]string{"entities", "path-context-assign", id, "--body", `{"context_id":"` + id + `"}`},
			"PUT /v1/tests/" + id + "/entity-context"},
	} {
		out, errs, code := run(t, srv, tc.args...)
		if code != 0 {
			t.Fatalf("%v exit=%d stderr=%s stdout=%s", tc.args, code, errs, out)
		}
		if got := <-seen; got != tc.want {
			t.Fatalf("%v routed %q, want %q", tc.args, got, tc.want)
		}
	}
}
