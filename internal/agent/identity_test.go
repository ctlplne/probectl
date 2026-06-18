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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// fakeControl serves a canned identity for /enroll/agent (no DB — the service
// itself is covered by the integration suite; THIS covers the client side).
func fakeControl(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req["token"] != "pjt_good" {
			http.Error(w, "invalid enrollment token", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cert_pem":  "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
			"ca_bundle": "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n",
			"spiffe_id": "spiffe://probectl/tenant/t-1/agent/a-1",
			"tenant_id": "t-1", "agent_id": "a-1", "serial": "ab12",
			"not_after": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano),
		})
	}))
	t.Cleanup(srv.Close)
	pin := hex.EncodeToString(crypto.Hash(srv.Certificate().Raw))
	return srv, pin
}

// SEC posture: enrollment writes the identity dir 0600/0700 and the SPIFFE id
// comes back; the pin authenticates the server on first contact.
func TestEnrollWritesIdentityWithPin(t *testing.T) {
	srv, pin := fakeControl(t)
	dir := filepath.Join(t.TempDir(), "identity")

	spiffe, notAfter, err := Enroll(context.Background(), EnrollOptions{
		Server: srv.URL, Token: "pjt_good", Dir: dir, Hostname: "h1", CAPin: pin,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if spiffe != "spiffe://probectl/tenant/t-1/agent/a-1" || time.Until(notAfter) < time.Hour {
		t.Fatalf("identity wrong: %s %s", spiffe, notAfter)
	}
	for _, f := range []string{IdentityCertFile, IdentityKeyFile, IdentityCAFile} {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("missing %s: %v", f, err)
		}
		if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want 0600", f, fi.Mode().Perm())
		}
	}
	// The key stayed local: it parses as a key and was never in the response.
	key, _ := os.ReadFile(filepath.Join(dir, IdentityKeyFile))
	if len(key) == 0 || string(key[:5]) != "-----" {
		t.Fatal("local key missing/garbled")
	}
}

// A WRONG pin must refuse before anything is sent (no TOFU fallback).
func TestEnrollRefusesPinMismatch(t *testing.T) {
	srv, _ := fakeControl(t)
	wrong := hex.EncodeToString(crypto.Hash([]byte("not the server cert")))
	_, _, err := Enroll(context.Background(), EnrollOptions{
		Server: srv.URL, Token: "pjt_good", Dir: t.TempDir(), CAPin: wrong,
	})
	if err == nil {
		t.Fatal("pin mismatch was accepted (first-contact trust broken)")
	}
}

func TestEnrollRejectsPlaintextServerByDefault(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	_, _, err := Enroll(context.Background(), EnrollOptions{
		Server: "http://127.0.0.1:1", Token: "pjt_good", Dir: dir, Hostname: "h1",
	})
	if err == nil || !strings.Contains(err.Error(), "plaintext http:// enrollment is refused") {
		t.Fatalf("plaintext server should be refused before network use, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, IdentityKeyFile)); !os.IsNotExist(err) {
		t.Fatal("identity material written despite plaintext URL refusal")
	}
}

func TestEnrollPlaintextOverrideIsLoopbackOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "identity")
	_, _, err := Enroll(context.Background(), EnrollOptions{
		Server:                 "http://control.example:8443",
		Token:                  "pjt_good",
		Dir:                    dir,
		Hostname:               "h1",
		AllowPlaintextLoopback: true,
	})
	if err == nil || !strings.Contains(err.Error(), "limited to localhost/loopback") {
		t.Fatalf("non-loopback plaintext override should be refused, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, IdentityKeyFile)); !os.IsNotExist(err) {
		t.Fatal("identity material written despite non-loopback plaintext URL refusal")
	}
}

func TestEnrollAllowsPlaintextLoopbackWithExplicitOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/enroll/agent" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cert_pem":  "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
			"ca_bundle": "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n",
			"spiffe_id": "spiffe://probectl/tenant/t-1/agent/a-1",
			"tenant_id": "t-1", "agent_id": "a-1", "serial": "ab12",
			"not_after": time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339Nano),
		})
	}))
	defer srv.Close()

	dir := filepath.Join(t.TempDir(), "identity")
	if _, _, err := Enroll(context.Background(), EnrollOptions{
		Server:                 srv.URL,
		Token:                  "pjt_good",
		Dir:                    dir,
		Hostname:               "h1",
		AllowPlaintextLoopback: true,
	}); err != nil {
		t.Fatalf("explicit loopback override should allow local dev enrollment: %v", err)
	}
	if !identityPresent(dir) {
		t.Fatal("loopback plaintext override did not write the enrolled identity")
	}
}

// A rejected token surfaces the server refusal (and writes nothing).
func TestEnrollBadTokenWritesNothing(t *testing.T) {
	srv, pin := fakeControl(t)
	dir := filepath.Join(t.TempDir(), "identity")
	if _, _, err := Enroll(context.Background(), EnrollOptions{
		Server: srv.URL, Token: "pjt_wrong", Dir: dir, CAPin: pin,
	}); err == nil {
		t.Fatal("bad token accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, IdentityKeyFile)); !os.IsNotExist(err) {
		t.Fatal("identity material written despite refusal")
	}
}

// RotationDue pins the 2/3-lifetime policy (ADR decision 3).
func TestRotationDueSVIDPolicy(t *testing.T) {
	nb := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(24 * time.Hour)
	if RotationDue(nb, na, nb.Add(8*time.Hour)) {
		t.Fatal("rotation due at 1/3 lifetime (too eager)")
	}
	if !RotationDue(nb, na, nb.Add(17*time.Hour)) {
		t.Fatal("rotation NOT due past 2/3 lifetime")
	}
	if !RotationDue(nb, na, na.Add(time.Hour)) {
		t.Fatal("rotation NOT due after expiry")
	}
}

func TestRotateRejectsPlaintextServerBeforeReadingIdentity(t *testing.T) {
	if _, err := Rotate(context.Background(), "http://127.0.0.1:1", "missing-cert", "missing-key", "missing-ca"); err == nil ||
		!strings.Contains(err.Error(), "plaintext http:// enrollment is refused") {
		t.Fatalf("rotation should reject plaintext server before reading identity files, got %v", err)
	}
}
