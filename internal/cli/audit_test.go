// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

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
