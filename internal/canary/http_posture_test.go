// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package canary_test

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/threat"
)

// TestHTTPCanaryCapturesLegacyTLSPosture is the RTP-18 regression. The request
// transport floors at TLS 1.2 + the secure cipher set, so a server that only
// speaks TLS 1.0/1.1 or a weak cipher is rejected at NEGOTIATION (before the
// cert is ever captured), and probectl used to produce no posture at all for
// it — the FindingDeprecatedTLS / FindingWeakCipher kinds were defined but the
// live path never reached them. The fix is a record-only posture handshake on
// that failure.
//
// This drives the REAL path end to end: the HTTP canary captures the posture,
// threat.FromCanaryAttributes rebuilds the observation (the exact S27 reuse of
// captured data — never a fresh handshake of its own), and the analyzer
// classifies it. Before the fix the failed probe captures no TLS attributes,
// FromCanaryAttributes returns ok=false, and the deprecated_protocol /
// weak_cipher assertions fail.
func TestHTTPCanaryCapturesLegacyTLSPosture(t *testing.T) {
	analyzer := threat.NewAnalyzer(threat.Config{}, nil)

	t.Run("tls_1_1_only_server_yields_deprecated_protocol", func(t *testing.T) {
		// Emulate a legacy device that only offers TLS 1.1. Go 1.26 disables its
		// own TLS 1.1 *server* by default (a real legacy endpoint speaks 1.1 on
		// its own; here we re-enable Go's server support to stand one up). The
		// canary's posture peek offers TLS 1.0+ as a CLIENT either way.
		t.Setenv("GODEBUG", "tls10server=1,tls11server=1")
		srv := startTLSServer(t, &tls.Config{MaxVersion: tls.VersionTLS11})

		res := runCanary(t, srv.URL, nil)
		if res.Success {
			t.Fatalf("a TLS 1.1-only server must fail the floored probe, got success=true")
		}
		kinds := classifyPosture(t, analyzer, res)
		if !kinds[threat.FindingDeprecatedTLS] {
			t.Fatalf("deprecated_protocol not surfaced; captured version=%q cipher=%q findings=%v",
				res.Attributes["tls.protocol.version"], res.Attributes["tls.cipher.suite"], keys(kinds))
		}
		if kinds[threat.FindingWeakCipher] {
			t.Fatalf("TLS 1.1 + a strong cipher must not be flagged weak_cipher; findings=%v", keys(kinds))
		}
	})

	t.Run("weak_cipher_only_server_yields_weak_cipher", func(t *testing.T) {
		// RC4 over TLS 1.2: the floored request shares no cipher with the server
		// and is rejected; the posture peek offers the broad set and negotiates it.
		srv := startTLSServer(t, &tls.Config{
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_RSA_WITH_RC4_128_SHA},
		})

		res := runCanary(t, srv.URL, nil)
		if res.Success {
			t.Fatalf("a weak-cipher-only server must fail the floored probe, got success=true")
		}
		kinds := classifyPosture(t, analyzer, res)
		if !kinds[threat.FindingWeakCipher] {
			t.Fatalf("weak_cipher not surfaced; captured version=%q cipher=%q findings=%v",
				res.Attributes["tls.protocol.version"], res.Attributes["tls.cipher.suite"], keys(kinds))
		}
		if kinds[threat.FindingDeprecatedTLS] {
			t.Fatalf("a TLS 1.2 handshake must not be flagged deprecated_protocol; findings=%v", keys(kinds))
		}
	})

	t.Run("modern_server_yields_neither", func(t *testing.T) {
		// A healthy modern server: the main handshake succeeds (captured via the
		// normal path, not the posture peek) and neither posture kind appears.
		srv := startTLSServer(t, nil)
		caFile := trustServerCert(t, srv)

		res := runCanary(t, srv.URL, map[string]string{"ca_file": caFile})
		if !res.Success {
			t.Fatalf("a modern trusted server must succeed, got success=false err=%q", res.Error)
		}
		kinds := classifyPosture(t, analyzer, res)
		if kinds[threat.FindingDeprecatedTLS] || kinds[threat.FindingWeakCipher] {
			t.Fatalf("a modern handshake must surface neither posture kind, got %v", keys(kinds))
		}
	})
}

// startTLSServer starts an HTTPS test server with the given server-side TLS
// config (nil → httptest's modern default), silencing the handshake-error log
// the intentional negotiation failures would otherwise spray to stderr.
func startTLSServer(t *testing.T, cfg *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	if cfg != nil {
		srv.TLS = cfg
	}
	srv.StartTLS()
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	return srv
}

// runCanary drives the real HTTP canary against target. allow_private_targets
// is set because the test servers are loopback (the audited U-002 override).
func runCanary(t *testing.T, target string, params map[string]string) canary.Result {
	t.Helper()
	if params == nil {
		params = map[string]string{}
	}
	params[canary.AllowPrivateParam] = "true"
	c, err := canary.NewHTTP(canary.Config{Type: "http", Target: target, Timeout: 5 * time.Second, Params: params})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned an internal error (probe failures must be success=false): %v", err)
	}
	return res
}

// classifyPosture runs the real S27 reuse path: rebuild the TLS observation from
// the canary's captured attributes, then analyze it into posture findings.
// Returns the set of finding kinds present (empty when nothing was captured,
// which is the pre-fix behavior for a rejected legacy/weak handshake).
func classifyPosture(t *testing.T, analyzer *threat.Analyzer, res canary.Result) map[threat.FindingKind]bool {
	t.Helper()
	kinds := map[threat.FindingKind]bool{}
	obs, ok := threat.FromCanaryAttributes(res.Target, res.Attributes, res.StartedAt)
	if !ok {
		return kinds
	}
	for _, f := range analyzer.Analyze(context.Background(), obs).Findings {
		kinds[f.Kind] = true
	}
	return kinds
}

// trustServerCert writes the server's (self-signed) leaf as a ca_file in an
// allowlisted dir so the canary trusts the modern test server and the probe
// genuinely succeeds. Mirrors a real agent's tls.canary_ca_dir allowlist.
func trustServerCert(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	leaf := srv.Certificate()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	canary.SetCAFileDir(dir)
	t.Cleanup(func() { canary.SetCAFileDir("") })
	return caFile
}

func keys(m map[threat.FindingKind]bool) []threat.FindingKind {
	out := make([]threat.FindingKind, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
