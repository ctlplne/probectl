// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/evidence"
	"github.com/ctlplne/probectl/internal/incident"
)

func TestIncidentCorrelationOverrideCommands(t *testing.T) {
	requests := make(chan map[string]any, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode body: %v", err)
		}
		requests <- map[string]any{"method": r.Method, "path": r.URL.EscapedPath(), "body": body}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"override-1","active":true}`))
	}))
	t.Cleanup(server.Close)
	getenv := func(key string) string {
		if key == "PROBECTL_API_URL" {
			return server.URL
		}
		return ""
	}

	for _, tc := range []struct {
		name string
		args []string
		path string
		body map[string]any
	}{
		{
			name: "ungroup",
			args: []string{"incident", "ungroup", "incident/one", "signal/two", "--reason", "false positive"},
			path: "/v1/incidents/incident%2Fone/correlation-overrides",
			body: map[string]any{"signal_id": "signal/two", "reason": "false positive"},
		},
		{
			name: "reverse",
			args: []string{"incident", "reverse-override", "incident/one", "override/two", "--reason", "operator correction"},
			path: "/v1/incidents/incident%2Fone/correlation-overrides/override%2Ftwo/reverse",
			body: map[string]any{"reason": "operator correction"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := RunWithStdin(tc.args, getenv, bytes.NewReader(nil), &stdout, &stderr); code != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			got := <-requests
			if got["method"] != http.MethodPost || got["path"] != tc.path {
				t.Fatalf("request = %#v", got)
			}
			if !jsonEqual(got["body"], tc.body) {
				t.Fatalf("body = %#v, want %#v", got["body"], tc.body)
			}
		})
	}
}

func jsonEqual(a, b any) bool {
	aJSON, _ := json.Marshal(a)
	bJSON, _ := json.Marshal(b)
	return bytes.Equal(aJSON, bJSON)
}

func TestIncidentVerifyOfflineAndTrustedFingerprint(t *testing.T) {
	privatePEM, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	manifest, attachments, err := evidence.Build(evidence.BuildInput{
		TenantID: "tenant-a", CreatedAt: now,
		Incident: incident.Incident{ID: "inc-1", StartedAt: now, LastSeenAt: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := evidence.Sign(manifest, attachments, privatePEM)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "package.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var pkg evidence.Package
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{name: "integrity only", args: []string{"incident", "verify", path}, code: 3, want: "INTEGRITY-ONLY probectl-evidence/v1"},
		{name: "trusted signer", args: []string{"incident", "verify", path, "--trusted-key-fingerprint", pkg.Signing.Fingerprint}, code: 0, want: "VERIFIED probectl-evidence/v1"},
		{name: "wrong signer", args: []string{"incident", "verify", path, "--trusted-key-fingerprint", "sha256:wrong"}, code: 1, want: "does not match trusted fingerprint"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := RunWithStdin(tc.args, func(string) string { return "" }, bytes.NewReader(nil), &stdout, &stderr)
			if code != tc.code || !strings.Contains(stdout.String()+stderr.String(), tc.want) {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

// TestIncidentVerifyUnpinnedIsNotAuthenticated proves AUD-19: a package signed
// with an attacker's OWN key passes integrity (evidence.Verify checks only the
// embedded key), so an unpinned `incident verify` must NOT report it VERIFIED
// and must exit non-zero — otherwise a forged package is indistinguishable from
// a genuine one. Only a pinned fingerprint that matches yields VERIFIED/exit 0.
func TestIncidentVerifyUnpinnedIsNotAuthenticated(t *testing.T) {
	// A "forged" package: a real-looking incident signed with a key the
	// operator never published (the attacker's own Ed25519 key).
	forgedPriv, _, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	manifest, attachments, err := evidence.Build(evidence.BuildInput{
		TenantID: "tenant-a", CreatedAt: now,
		Incident: incident.Incident{ID: "inc-forged", StartedAt: now, LastSeenAt: now},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := evidence.Sign(manifest, attachments, forgedPriv)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "forged.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var pkg evidence.Package
	if err := json.Unmarshal(raw, &pkg); err != nil {
		t.Fatal(err)
	}

	// Unpinned: the forged package is internally consistent, so integrity
	// passes — but it must NOT be presented as verified, and must exit non-zero.
	var stdout, stderr bytes.Buffer
	code := RunWithStdin([]string{"incident", "verify", path}, func(string) string { return "" }, bytes.NewReader(nil), &stdout, &stderr)
	if code == 0 {
		t.Fatalf("unpinned verify of a forged package exited 0 (treated as trusted): stdout=%q", stdout.String())
	}
	if strings.Contains(stdout.String(), "VERIFIED") {
		t.Fatalf("unpinned verify printed VERIFIED for an unauthenticated package: %q", stdout.String())
	}
	if !strings.Contains(stdout.String(), "INTEGRITY-ONLY") {
		t.Fatalf("unpinned verify did not state the signer is unauthenticated: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}

	// Pinning the forged package's OWN fingerprint prints VERIFIED (the pin is
	// the operator's attestation of which key to trust) — proving the gate is
	// the pin, and that an operator who pins the genuine fingerprint instead
	// would reject this forgery (the "wrong signer" case above).
	stdout.Reset()
	stderr.Reset()
	code = RunWithStdin([]string{"incident", "verify", path, "--trusted-key-fingerprint", pkg.Signing.Fingerprint},
		func(string) string { return "" }, bytes.NewReader(nil), &stdout, &stderr)
	if code != 0 || !strings.Contains(stdout.String(), "VERIFIED") {
		t.Fatalf("pinned verify of its own fingerprint should succeed: code=%d stdout=%q", code, stdout.String())
	}
}
