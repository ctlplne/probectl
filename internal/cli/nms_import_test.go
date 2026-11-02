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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNMSImportCLIKeepsReferenceOutOfArgvAndRoutesScopedReads(t *testing.T) {
	const contextID = "00000000-0000-4000-8000-000000000101"
	const planID = "00000000-0000-4000-8000-000000000102"
	body := `{"context_id":"` + contextID + `","instance_ref":"lab","https_origin":"https://nms.example.test","credential_ref":"vault:probectl/nms/tenant/token"}`
	seen := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Method + " " + r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/nms-imports/sources" {
			var got map[string]any
			if json.NewDecoder(r.Body).Decode(&got) != nil || got["credential_ref"] != "vault:probectl/nms/tenant/token" {
				t.Error("configuration body was not forwarded from the owner-only file")
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"source_id":"` + planID + `"}`))
			return
		}
		_, _ = w.Write([]byte(`{"context_id":"` + contextID + `","plan_id":"` + planID + `","snapshot_hash":"` + strings.Repeat("a", 64) + `","row_count":0,"items":[]}`))
	}))
	t.Cleanup(srv.Close)
	if _, stderr, code := run(t, srv, "nms-import", "configure-source", "--body", body); code != 2 ||
		!strings.Contains(stderr, "refuses --body") || len(seen) != 0 {
		t.Fatalf("inline reference was accepted: exit=%d stderr=%q requests=%v", code, stderr, seen)
	}
	if _, stderr, code := run(t, srv, "api", "POST", "/v1/nms-imports/sources", "--body", body); code != 2 ||
		!strings.Contains(stderr, "refuses --body") || len(seen) != 0 {
		t.Fatalf("generic API bypass accepted inline reference: exit=%d stderr=%q requests=%v", code, stderr, seen)
	}
	path := filepath.Join(t.TempDir(), "source.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := run(t, srv, "nms-import", "configure-source", "--body-file", path)
	if code != 0 || strings.Contains(stdout+stderr, "vault:") || len(seen) != 1 {
		t.Fatalf("owner-file configuration: exit=%d stdout=%q stderr=%q requests=%v", code, stdout, stderr, seen)
	}
	if got := <-seen; got != "POST /v1/nms-imports/sources" {
		t.Fatalf("configuration route = %q", got)
	}
	if _, stderr, code := run(t, srv, "nms-import", "rows", planID,
		"--query", "context_id="+contextID, "--query", "limit=1"); code != 0 ||
		stderr != "" || len(seen) != 1 {
		t.Fatalf("scoped sealed rows: exit=%d stderr=%q requests=%v", code, stderr, seen)
	}
	if got := <-seen; got != "GET /v1/nms-imports/"+planID+"/rows?context_id="+contextID+"&limit=1" {
		t.Fatalf("sealed-row route = %q", got)
	}
	if _, stderr, code := run(t, srv, "nms-import", "poll-proposals",
		"--query", "context_id="+contextID, "--query", "source_id="+planID,
		"--query", "limit=1"); code != 0 || stderr != "" || len(seen) != 1 {
		t.Fatalf("scoped poll proposals: exit=%d stderr=%q requests=%v", code, stderr, seen)
	}
	got := <-seen
	method, requestURI, found := strings.Cut(got, " ")
	parsed, err := url.ParseRequestURI(requestURI)
	if !found || err != nil || method != http.MethodGet || parsed.Path != "/v1/nms-imports/poll-proposals" ||
		parsed.Query().Get("context_id") != contextID || parsed.Query().Get("source_id") != planID ||
		parsed.Query().Get("limit") != "1" || len(parsed.Query()) != 3 {
		t.Fatalf("proposal-list route = %q", got)
	}
	if _, stderr, code := run(t, srv, "nms-import", "advance", planID,
		"--body", `{"context_id":"`+contextID+`"}`); code != 0 || stderr != "" || len(seen) != 1 {
		t.Fatalf("scoped advance: exit=%d stderr=%q requests=%v", code, stderr, seen)
	}
	if got := <-seen; got != "POST /v1/nms-imports/"+planID+"/advance" {
		t.Fatalf("advance route = %q", got)
	}
	review := `{"context_id":"` + contextID + `","snapshot_hash":"` + strings.Repeat("a", 64) +
		`","choices":[{"row_number":0,"action":"skip"}]}`
	if _, stderr, code := run(t, srv, "nms-import", "review-choices", planID,
		"--body", review); code != 0 || stderr != "" || len(seen) != 1 {
		t.Fatalf("scoped review choices: exit=%d stderr=%q requests=%v", code, stderr, seen)
	}
	if got := <-seen; got != "POST /v1/nms-imports/"+planID+"/review-choices" {
		t.Fatalf("review route = %q", got)
	}
	if _, stderr, code := run(t, srv, "nms-import", "finalize-review", planID,
		"--body", `{"context_id":"`+contextID+`","snapshot_hash":"`+strings.Repeat("a", 64)+`"}`); code != 0 || stderr != "" || len(seen) != 1 {
		t.Fatalf("scoped review finalize: exit=%d stderr=%q requests=%v", code, stderr, seen)
	}
	if got := <-seen; got != "POST /v1/nms-imports/"+planID+"/finalize-review" {
		t.Fatalf("review finalize route = %q", got)
	}
	verify := `{"context_id":"` + contextID + `","snapshot_hash":"` + strings.Repeat("a", 64) +
		`","review_hash":"` + strings.Repeat("b", 64) + `"}`
	if _, stderr, code := run(t, srv, "nms-import", "verify-before-apply", planID,
		"--body", verify); code != 0 || stderr != "" || len(seen) != 1 {
		t.Fatalf("scoped source re-verification: exit=%d stderr=%q requests=%v", code, stderr, seen)
	}
	if got := <-seen; got != "POST /v1/nms-imports/"+planID+"/verify-before-apply" {
		t.Fatalf("source re-verification route = %q", got)
	}
	if _, stderr, code := run(t, srv, "nms-import", "apply", planID,
		"--body", verify); code != 0 || stderr != "" || len(seen) != 1 {
		t.Fatalf("scoped apply: exit=%d stderr=%q requests=%v", code, stderr, seen)
	}
	if got := <-seen; got != "POST /v1/nms-imports/"+planID+"/apply" {
		t.Fatalf("apply route = %q", got)
	}
}
