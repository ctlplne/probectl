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
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ctlplne/probectl/internal/auth"
)

const cliIREventRef = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestAuditRevealReadsReasonFromStdinAndCallsTenantEndpoint(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, request *http.Request) {
			requests.Add(1)
			if request.Method != http.MethodPost ||
				request.URL.Path != "/v1/audit/ir/"+cliIREventRef+"/reveal" {
				t.Errorf("request = %s %s", request.Method, request.URL.Path)
				return
			}
			session, err := request.Cookie(auth.SessionCookie)
			if err != nil || session.Value != "mfa-session-token" ||
				request.Header.Get("Authorization") != "" ||
				request.Header.Get("X-Probectl-Tenant") !=
					"00000000-0000-0000-0000-0000000000a1" {
				t.Errorf("request headers = %#v", request.Header)
				return
			}
			var body struct {
				Reason string `json:"reason"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Error(err)
				return
			}
			if body.Reason != "investigate privileged abuse" {
				t.Errorf("reason = %q", body.Reason)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(
				w,
				`{"operator":"operator-canary@example.test","tenant_id":"00000000-0000-0000-0000-0000000000a1","grant":"grant-7","surface":"results.latest","consent":"tenant-approved","outcome":"accessed","reason":"original break-glass reason","event_ref":"`+
					cliIREventRef+
					`","ts":"2026-07-30T12:00:00Z"}`,
			)
		},
	))
	t.Cleanup(server.Close)
	sessionPath := filepath.Join(t.TempDir(), "session.cookie")
	if err := os.WriteFile(
		sessionPath,
		[]byte("mfa-session-token\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := RunWithStdin(
		[]string{
			"--url", server.URL,
			"--token", "test-token",
			"--tenant", "00000000-0000-0000-0000-0000000000a1",
			"audit", "reveal", cliIREventRef,
			"--session-cookie-file", sessionPath,
		},
		func(string) string { return "" },
		strings.NewReader(" investigate privileged abuse \n"),
		&stdout,
		&stderr,
	)
	if code != 0 {
		t.Fatalf("exit = %d stderr=%s", code, stderr.String())
	}
	if requests.Load() != 1 ||
		!strings.Contains(stdout.String(), "operator-canary@example.test") {
		t.Fatalf(
			"requests=%d stdout=%s stderr=%s",
			requests.Load(),
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestAuditRevealReasonFileMustBeOwnerOnlyRegularFile(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			requests.Add(1)
			_, _ = io.WriteString(w, `{}`)
		},
	))
	t.Cleanup(server.Close)
	directory := t.TempDir()
	reasonPath := filepath.Join(directory, "reason.txt")
	if err := os.WriteFile(
		reasonPath,
		[]byte("investigate privileged abuse\n"),
		0o644,
	); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := RunWithStdin(
		[]string{
			"--url", server.URL,
			"audit", "reveal", cliIREventRef,
			"--reason-file", reasonPath,
		},
		func(string) string { return "" },
		strings.NewReader("must-not-be-used"),
		&stdout,
		&stderr,
	)
	if code != 2 ||
		!strings.Contains(stderr.String(), "want 0600") ||
		requests.Load() != 0 {
		t.Fatalf(
			"exit=%d requests=%d stderr=%s",
			code,
			requests.Load(),
			stderr.String(),
		)
	}
}

func TestAuditRevealRejectsBearerOnlyBeforeNetwork(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(
		func(http.ResponseWriter, *http.Request) {
			requests.Add(1)
		},
	))
	t.Cleanup(server.Close)
	var stdout, stderr bytes.Buffer
	code := RunWithStdin(
		[]string{
			"--url", server.URL,
			"--token", "bearer-cannot-attest-mfa",
			"audit", "reveal", cliIREventRef,
		},
		func(string) string { return "" },
		strings.NewReader("investigate privileged abuse"),
		&stdout,
		&stderr,
	)
	if code != 2 ||
		requests.Load() != 0 ||
		!strings.Contains(stderr.String(), "do not attest MFA") {
		t.Fatalf(
			"exit=%d requests=%d stderr=%s",
			code,
			requests.Load(),
			stderr.String(),
		)
	}
}

// TestProviderConsentCommandsUseTheTenantSession: the tenant side of
// break-glass consent authenticates ONLY with the tenant user's session cookie
// (AUD-13) — the provider handler never accepts a bearer token there. The
// consent commands used to send the bearer token like every other command, so
// `probectl provider consent|decide-consent` could never authenticate. They now
// send the cookie from --session-cookie-file and refuse to run without one.
func TestProviderConsentCommandsUseTheTenantSession(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		session, err := request.Cookie(auth.SessionCookie)
		if err != nil || session.Value != "tenant-admin-session" || request.Header.Get("Authorization") != "" {
			t.Errorf("%s %s: cookie=%v authorization=%q, want the session cookie and no bearer token",
				request.Method, request.URL.Path, session, request.Header.Get("Authorization"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		seen = append(seen, request.Method+" "+request.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"items":[]}`)
	}))
	t.Cleanup(server.Close)
	sessionPath := filepath.Join(t.TempDir(), "session.cookie")
	if err := os.WriteFile(sessionPath, []byte("tenant-admin-session\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(env map[string]string, args ...string) (int, string) {
		t.Helper()
		var stdout, stderr bytes.Buffer
		code := RunWithStdin(append([]string{"--url", server.URL, "--token", "operator-token", "--json"}, args...),
			func(k string) string { return env[k] }, strings.NewReader(""), &stdout, &stderr)
		return code, stderr.String()
	}
	for _, args := range [][]string{
		{"provider", "consent", "--session-cookie-file", sessionPath},
		{"provider", "decide-consent", "11111111-1111-1111-1111-111111111111", "--body", `{"decision":"approve"}`, "--session-cookie-file", sessionPath},
		{"provider", "revoke-consent", "11111111-1111-1111-1111-111111111111", "--session-cookie-file", sessionPath},
	} {
		if code, stderr := run(nil, args...); code != 0 {
			t.Fatalf("%v: exit %d stderr=%s", args, code, stderr)
		}
	}
	// The environment variable works the same as the flag.
	if code, stderr := run(map[string]string{"PROBECTL_SESSION_COOKIE_FILE": sessionPath}, "provider", "consent"); code != 0 {
		t.Fatalf("PROBECTL_SESSION_COOKIE_FILE: exit %d stderr=%s", code, stderr)
	}
	want := []string{
		"GET /provider/v1/consent",
		"POST /provider/v1/consent/11111111-1111-1111-1111-111111111111",
		"POST /provider/v1/consent/11111111-1111-1111-1111-111111111111/revoke",
		"GET /provider/v1/consent",
	}
	if strings.Join(seen, "|") != strings.Join(want, "|") {
		t.Fatalf("requests = %v, want %v", seen, want)
	}
	// Without a session cookie the command refuses before any request: a bearer
	// token can never satisfy these routes.
	code, stderr := run(nil, "provider", "consent")
	if code != 2 || !strings.Contains(stderr, "--session-cookie-file or PROBECTL_SESSION_COOKIE_FILE is required") {
		t.Fatalf("no session cookie: exit %d stderr=%s", code, stderr)
	}
	if len(seen) != len(want) {
		t.Fatalf("a request was sent without a session cookie: %v", seen)
	}
}
