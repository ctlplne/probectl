// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
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
	// DPR-021: the pinned server certificate is persisted as the server trust
	// the runtime verifies the gRPC listener with.
	serverCA, err := os.ReadFile(filepath.Join(dir, IdentityServerCAFile))
	if err != nil {
		t.Fatalf("server trust not persisted: %v", err)
	}
	block, _ := pem.Decode(serverCA)
	if block == nil || block.Type != "CERTIFICATE" || !bytes.Equal(block.Bytes, srv.Certificate().Raw) {
		t.Fatal("server-ca.pem must hold the certificate the pinned enrollment verified")
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

// DPR-020: the join token is single-use, so an unwritable identity directory
// must be refused BEFORE the control plane is asked to redeem it.
func TestEnrollRefusesUnwritableDirBeforeRedeemingToken(t *testing.T) {
	var requests int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&requests, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	pin := fmt.Sprintf("%x", crypto.Hash(srv.Certificate().Raw))
	// A regular file where the directory should be: MkdirAll fails.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Enroll(context.Background(), EnrollOptions{
		Server: srv.URL, Token: "pjt_single_use", Dir: filepath.Join(blocker, "identity"), CAPin: pin,
	})
	if err == nil {
		t.Fatal("an unusable identity directory must be refused")
	}
	if !strings.Contains(err.Error(), "nothing was redeemed") {
		t.Fatalf("refusal must say the token was not consumed, got: %v", err)
	}
	if n := atomic.LoadInt32(&requests); n != 0 {
		t.Fatalf("the control plane must not be contacted before the directory is proven writable (got %d requests)", n)
	}
}

// DPR-021: with --ca-file the same bundle is persisted as the server trust,
// so the printed config snippet points the runtime at a file that verifies
// the control plane rather than at the agent-CA bundle.
func TestEnrollPersistsServerTrustFromCAFile(t *testing.T) {
	srv, _ := fakeControl(t)
	caFile := filepath.Join(t.TempDir(), "server-ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "identity")
	if _, _, err := Enroll(context.Background(), EnrollOptions{
		Server: srv.URL, Token: "pjt_good", Dir: dir, Hostname: "h1", CAFile: caFile,
	}); err != nil {
		t.Fatalf("enroll with --ca-file: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, IdentityServerCAFile))
	if err != nil {
		t.Fatalf("server trust not persisted: %v", err)
	}
	if !bytes.Equal(got, caPEM) {
		t.Fatal("server-ca.pem must be the --ca-file bundle")
	}
	agentCA, _ := os.ReadFile(filepath.Join(dir, IdentityCAFile))
	if bytes.Equal(agentCA, caPEM) {
		t.Fatal("the agent-CA bundle and the server trust are different files with different jobs")
	}
}
