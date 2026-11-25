// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestProviderBrandCommandsKeepTenantAndStrongRevision(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const sibling = "22222222-2222-4222-8222-222222222222"
	requests := make(chan string, 5)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Method + " " + r.URL.Path + " " + r.Header.Get("If-Match")
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("ETag", `"0"`)
			_, _ = io.WriteString(w, `{"name":"Original brand"}`)
		case http.MethodPut:
			if r.Header.Get("If-Match") != `"0"` {
				w.WriteHeader(http.StatusConflict)
				return
			}
			var brand map[string]string
			if err := json.NewDecoder(r.Body).Decode(&brand); err != nil || !reflect.DeepEqual(brand, map[string]string{"name": "New brand"}) {
				t.Error("replacement body lost its brand document", err)
			}
			w.Header().Set("ETag", `"1"`)
			_, _ = io.WriteString(w, `{"name":"New brand"}`)
		}
	}))
	defer server.Close()
	run := func(args ...string) (int, string, string) {
		t.Helper()
		var out, errOut bytes.Buffer
		flags := []string{"--url", server.URL, "--json", "provider"}
		code := RunWithStdin(append(flags, args...), func(string) string { return "" }, strings.NewReader(""), &out, &errOut)
		return code, out.String(), errOut.String()
	}
	code, output, errOut := run("brand", tenant)
	if code != 0 || !strings.Contains(output, `"revision": "0"`) || !strings.Contains(output, "Original brand") {
		t.Fatalf("read lost the brand or revision: %d %s %s", code, output, errOut)
	}
	if code, _, _ := run("set-brand", sibling, "--body", `{"name":"New brand"}`); code == 0 {
		t.Fatal("a write without a revision succeeded")
	}
	if code, _, _ := run("set-brand", sibling, "--revision", "1", "--body", `{"name":"New brand"}`); code == 0 {
		t.Fatal("a stale revision succeeded")
	}
	code, output, errOut = run("set-brand", tenant, "--revision", "0", "--body", `{"name":"New brand"}`)
	if code != 0 || !strings.Contains(output, `"revision": "1"`) || !strings.Contains(output, "New brand") {
		t.Fatalf("replace lost the brand or revision: %d %s %s", code, output, errOut)
	}
	close(requests)
	var seen []string
	for request := range requests {
		seen = append(seen, request)
	}
	want := []string{
		"GET /provider/v1/tenants/" + tenant + "/brand ",
		"PUT /provider/v1/tenants/" + sibling + `/brand "1"`,
		"PUT /provider/v1/tenants/" + tenant + `/brand "0"`,
	}
	if !reflect.DeepEqual(seen, want) {
		t.Fatalf("tenant or revision changed on the wire: %v", seen)
	}
}
