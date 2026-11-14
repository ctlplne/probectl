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
	"strings"
	"testing"
)

func TestProviderMonthlyReportCommandsKeepTenantAndRetryIDs(t *testing.T) {
	const tenant = "11111111-1111-4111-8111-111111111111"
	const request = "22222222-2222-4222-8222-222222222222"
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-only-operator-session" {
			t.Error("operator session lost")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		seen = append(seen, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPost {
			var body struct {
				RequestID string `json:"request_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RequestID != request {
				t.Error("retry ID lost", err)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"tenant_id":"`+tenant+`","eligible":1,"queued":1,"pending":1,"delivered":0,"inactive":0,"replay":false}`)
	}))
	defer server.Close()
	for _, args := range [][]string{
		{"provider", "monthly-reports", tenant, "--body", `{"request_id":"` + request + `"}`},
		{"provider", "monthly-report-progress", tenant, request},
	} {
		var stdout, stderr bytes.Buffer
		code := RunWithStdin(append([]string{"--url", server.URL, "--json"}, args...), func(key string) string {
			if key == "PROBECTL_API_TOKEN" {
				return "test-only-operator-session"
			}
			return ""
		}, strings.NewReader(""), &stdout, &stderr)
		if code != 0 {
			t.Fatal("provider command failed", code, stderr.String())
		}
		if !strings.Contains(stdout.String(), tenant) {
			t.Fatal("provider result lost tenant metadata")
		}
	}
	want := []string{"POST /provider/v1/tenants/" + tenant + "/monthly-reports", "GET /provider/v1/tenants/" + tenant + "/monthly-reports/" + request}
	if strings.Join(seen, ";") != strings.Join(want, ";") {
		t.Fatal("provider route/verb changed", seen)
	}
}
