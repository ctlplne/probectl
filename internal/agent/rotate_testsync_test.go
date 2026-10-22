// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
)

// rotationFixture is an identity dir enrolled BEFORE central test distribution
// (no testsync.pub) plus a fake control plane that rotates it and returns key.
func rotationFixture(t *testing.T, key string) (dir, server, caFile string) {
	t.Helper()
	ca, err := crypto.GenerateCA("rotate-testsync-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(t.TempDir(), "identity")
	certPEM, keyPEM, err := ca.IssueClientCert("agent-1", crypto.AgentSPIFFEID("t-1", "agent-1"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeIdentityDir(dir, certPEM, keyPEM, ca.CertPEM()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"cert_pem": string(certPEM), "ca_bundle": string(ca.CertPEM()),
			"spiffe_id": crypto.AgentSPIFFEID("t-1", "agent-1"), "tenant_id": "t-1", "agent_id": "agent-1",
			"serial": "01", "not_after": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
			"testsync_public_key": key,
		})
	}))
	t.Cleanup(srv.Close)
	caFile = filepath.Join(t.TempDir(), "server-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, srv.URL, caFile
}

// G9 gap 5: an agent enrolled before central test distribution receives the
// test-bundle public key at its next identity rotation, written beside
// cert.pem, and the RUNNING agent turns central tests on without a restart.
func TestRotationDeliversTestSyncKeyToAnAgentEnrolledBefore(t *testing.T) {
	_, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	dir, server, caFile := rotationFixture(t, string(pub))
	certFile, keyFile := filepath.Join(dir, IdentityCertFile), filepath.Join(dir, IdentityKeyFile)

	// The running agent starts without a key: local canaries only.
	cfg := &Config{TLS: TLSConfig{CertFile: certFile}, Buffer: BufferConfig{Dir: filepath.Join(t.TempDir(), "buffer")}}
	cfg.TestSync.applyDefaults(certFile, cfg.Buffer.Dir)
	buf, err := openBuffer(cfg.Buffer.Dir, 100)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	reg := canary.NewRegistry()
	reg.Register("noop", canary.NewNoop)
	a := &Agent{cfg: cfg, log: log, buffer: buf, reg: reg, tenantID: "t-1",
		host: &Host{buffer: buf, tenantID: "t-1", log: log}}
	now := time.Now()
	if a.maybeStartSync(now) || a.sync != nil {
		t.Fatal("central tests must stay off while no test-bundle key is present")
	}

	if _, err := Rotate(context.Background(), server, certFile, keyFile, caFile); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, TestSyncPublicKeyFileName))
	if err != nil || !bytes.Equal(got, pub) {
		t.Fatalf("rotation did not write testsync.pub beside cert.pem: %q, %v", got, err)
	}

	if a.maybeStartSync(now.Add(time.Second)) {
		t.Fatal("the key probe must be rate-limited")
	}
	if !a.maybeStartSync(now.Add(testSyncProbeInterval)) || a.sync == nil {
		t.Fatal("the running agent did not turn central tests on after the key arrived")
	}
	if !a.sync.due(now) {
		t.Fatal("a freshly started test sync must pull at once")
	}

	// test_sync.enabled: false is never overridden by a delivered key.
	off := false
	b := &Agent{cfg: &Config{TestSync: cfg.TestSync}, log: log, reg: reg, host: a.host}
	b.cfg.TestSync.Enabled = &off
	if b.maybeStartSync(now.Add(time.Hour)) {
		t.Fatal("a delivered key turned on central tests that the operator disabled")
	}
}

// An unusable key in the rotation response refuses the whole rotation: the
// identity is not replaced and no key is written.
func TestRotationRefusesAnUnusableTestSyncKey(t *testing.T) {
	dir, server, caFile := rotationFixture(t, "-----BEGIN PUBLIC KEY-----\nbm90IGEga2V5\n-----END PUBLIC KEY-----\n")
	certFile, keyFile := filepath.Join(dir, IdentityCertFile), filepath.Join(dir, IdentityKeyFile)
	keyBefore, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(context.Background(), server, certFile, keyFile, caFile); err == nil {
		t.Fatal("rotation accepted an unusable test-bundle key")
	}
	keyAfter, err := os.ReadFile(keyFile)
	if err != nil || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("a refused rotation replaced the agent's key")
	}
	if _, err := os.Stat(filepath.Join(dir, TestSyncPublicKeyFileName)); err == nil {
		t.Fatal("an unusable key was written")
	}
}
