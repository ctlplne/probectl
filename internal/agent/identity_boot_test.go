// SPDX-License-Identifier: LicenseRef-probectl-TBD

package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

func TestIdentityPresent(t *testing.T) {
	dir := t.TempDir()
	if identityPresent(dir) {
		t.Fatal("empty dir must not look enrolled")
	}
	mustWriteFile(t, filepath.Join(dir, IdentityCertFile), "cert")
	if identityPresent(dir) {
		t.Fatal("cert without key must not look enrolled")
	}
	mustWriteFile(t, filepath.Join(dir, IdentityKeyFile), "key")
	if !identityPresent(dir) {
		t.Fatal("cert+key must look enrolled")
	}
}

func TestEnsureIdentityNoOpWhenPresent(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, IdentityCertFile), "cert")
	mustWriteFile(t, filepath.Join(dir, IdentityKeyFile), "key")
	// A server that would error if contacted — proves a present identity is
	// never overwritten and the server is never hit.
	if err := EnsureIdentity(context.Background(), EnrollOptions{
		Server: "https://127.0.0.1:1", Token: "pjt_x", Dir: dir,
	}, nil); err != nil {
		t.Fatalf("present identity must be a no-op, got %v", err)
	}
}

func TestEnsureIdentityNoOpWhenNoToken(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureIdentity(context.Background(), EnrollOptions{
		Server: "https://127.0.0.1:1", Token: "", Dir: dir,
	}, nil); err != nil {
		t.Fatalf("no token must be a no-op, got %v", err)
	}
	if identityPresent(dir) {
		t.Fatal("a no-op must not write an identity")
	}
}

func TestEnsureIdentityFailsFastOnDefinitive(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "invalid enrollment token", http.StatusUnauthorized) // 401 = definitive
	}))
	defer ts.Close()
	dir := t.TempDir()
	pin := hex.EncodeToString(crypto.Hash(ts.Certificate().Raw))
	start := time.Now()
	err := EnsureIdentity(context.Background(), EnrollOptions{
		Server: ts.URL, Token: "pjt_bad", Dir: dir, CAPin: pin,
	}, nil)
	if err == nil {
		t.Fatal("a definitive 401 must fail, not retry")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("definitive rejection must fail fast, took %s", time.Since(start))
	}
	if identityPresent(dir) {
		t.Fatal("a failed enrollment must not write an identity")
	}
}

func TestEnsureIdentitySuccessWritesIdentity(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enroll/agent" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cert_pem":  "-----BEGIN CERTIFICATE-----\nFAKELEAF\n-----END CERTIFICATE-----\n",
			"ca_bundle": "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n",
			"spiffe_id": "spiffe://probectl/tenant/t/agent/a",
			"not_after": time.Now().Add(24 * time.Hour),
		})
	}))
	defer ts.Close()
	dir := t.TempDir()
	pin := hex.EncodeToString(crypto.Hash(ts.Certificate().Raw))
	if err := EnsureIdentity(context.Background(), EnrollOptions{
		Server: ts.URL, Token: "pjt_ok", Dir: dir, CAPin: pin,
	}, nil); err != nil {
		t.Fatalf("success path: %v", err)
	}
	if !identityPresent(dir) {
		t.Fatal("a successful enrollment must write cert+key")
	}
}

func TestEnsureIdentityRetryRespectsContext(t *testing.T) {
	// Unreachable server + already-canceled context: the transient retry loop
	// must return promptly with the context error, not hang for the window.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := t.TempDir()
	start := time.Now()
	if err := EnsureIdentity(ctx, EnrollOptions{
		Server: "https://127.0.0.1:1", Token: "pjt_x", Dir: dir,
	}, nil); err == nil {
		t.Fatal("a canceled context must surface an error")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("a canceled context must return promptly, took %s", time.Since(start))
	}
}

func mustWriteFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
