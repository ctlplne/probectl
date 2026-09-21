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
		{name: "integrity only", args: []string{"incident", "verify", path}, code: 0, want: "NOTICE signer integrity is proven"},
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
