// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestLongOperationsOutliveTheDefaultRequestBudget (WEB-04): the CLI gave
// every request the same 15-second budget. It abandoned a verified erasure, a
// siloed provisioning, a path discovery or a remote-model answer that the
// server, which gives those routes a longer budget, was still running, and it
// cut every export download off at 15 seconds where the server allows 15
// minutes. A provisioning it abandoned left the tenant published with its
// roles unseeded. Each long operation must outlive the default budget; an
// ordinary call keeps it.
func TestLongOperationsOutliveTheDefaultRequestBudget(t *testing.T) {
	restore := defaultRequestTimeout
	defaultRequestTimeout = 150 * time.Millisecond
	t.Cleanup(func() { defaultRequestTimeout = restore })
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		if strings.HasSuffix(r.URL.Path, "/export") {
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = io.WriteString(w, "bundle-bytes")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	t.Cleanup(srv.Close)
	env := map[string]string{"PROBECTL_API_URL": srv.URL, "PROBECTL_API_TOKEN": "pat_test"}
	run := func(args ...string) (int, string) {
		var stdout, stderr bytes.Buffer
		code := RunWithStdin(append([]string{"--json"}, args...), func(k string) string { return env[k] },
			strings.NewReader(""), &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}
	for _, args := range [][]string{
		{"lifecycle", "erase", "--body", `{"confirm":"acme"}`},
		{"lifecycle", "subject-erase", "--subject", "alice@example.com", "--confirm", "alice@example.com", "--reason", "dsar"},
		{"lifecycle", "export"},
		{"provider", "create-tenant", "--body", `{"slug":"acme","name":"Acme","isolation_model":"siloed"}`},
		{"provider", "erase-tenant", "tn_1", "--body", `{"confirm":"acme"}`},
		{"tenant", "create", "--body", `{"slug":"acme","name":"Acme","isolation_model":"siloed"}`},
		{"tenant", "erase", "tn_1", "--body", `{"confirm":"acme"}`},
		{"test", "path", "t_1", "--body", `{}`},
		{"ai", "ask", "--body", `{"question":"why is checkout slow?"}`},
	} {
		if code, out := run(args...); code != 0 {
			t.Errorf("probectl %s was cut off by the default budget: exit %d: %s", strings.Join(args, " "), code, out)
		}
	}
	if code, out := run("me", "show"); code == 0 || !strings.Contains(out, "Timeout") {
		t.Errorf("an ordinary call lost the default budget: exit %d: %s", code, out)
	}
}
