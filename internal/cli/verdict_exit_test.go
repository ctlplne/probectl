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

// DPR-272: `probectl audit verify` printed "audit chain broken at seq 2: hash
// mismatch (record tampered)" and exited 0. The handler answers 200 on purpose —
// an integrity finding is data, not a transport failure — but a CLI's contract is
// its exit status, so every cron job and monitoring check that ran this command
// was told a compromised audit log was fine. Found by driving the real CLI in the
// two-tenant audit receipt rather than by calling the handler.
func TestAuditVerifyExitsNonZeroOnABrokenChain(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		body     string
		wantCode int
	}{
		{"broken chain", `{"ok":false,"detail":"audit chain broken at seq 2: hash mismatch (record tampered)"}`, 1},
		{"intact chain", `{"ok":true}`, 0},
		// A missing field must not be invented into a failure: absent is not false.
		{"no verdict field", `{"items":[]}`, 0},
		// A non-boolean value is not a verdict either.
		{"non-boolean verdict", `{"ok":"maybe"}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/audit/verify" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			env := map[string]string{"PROBECTL_API_URL": srv.URL, "PROBECTL_TENANT": "t-1"}
			var out strings.Builder
			code := RunWithStdin([]string{"audit", "verify"},
				func(k string) string { return env[k] }, strings.NewReader(""), &out, &out)
			if code != tc.wantCode {
				t.Errorf("exit = %d, want %d (output: %s)", code, tc.wantCode, out.String())
			}
			// The detail must reach the operator whatever the exit status is.
			if strings.Contains(tc.body, "chain broken") && !strings.Contains(out.String(), "chain broken") {
				t.Errorf("the finding was not printed: %s", out.String())
			}
		})
	}
}
