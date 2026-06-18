// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package canary_test

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/canary"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
)

// tlsServer starts an HTTPS test server presenting the given cert/key, and
// returns the server plus a path to a CA file the canary can trust.
func tlsServer(t *testing.T, certPEM, keyPEM, caPEM []byte, h http.Handler) (*httptest.Server, string) {
	t.Helper()
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	caDir := t.TempDir()
	caFile := filepath.Join(caDir, "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}
	// RED-008 (Sprint 12): the agent only honors a ca_file that resolves inside
	// an operator-allowlisted directory; unset = refused. Mirror a real agent
	// runtime (tls.canary_ca_dir / PROBECTL_AGENT_CANARY_CA_DIR) by allowlisting
	// this CA's temp dir, so the probe still exercises the full ca_file path.
	canary.SetCAFileDir(caDir)
	t.Cleanup(func() { canary.SetCAFileDir("") })
	return srv, caFile
}

func runHTTP(t *testing.T, target string, params map[string]string) canary.Result {
	t.Helper()
	if params == nil {
		params = map[string]string{}
	}
	params["allow_private_targets"] = "true" // loopback test servers (U-002 override, audited in prod)
	// WIRE-004: when a test opts a probe into insecure_skip_verify, mirror the
	// agent-level opt-in the runtime would require.
	allowInsecure := params["insecure_skip_verify"] == "true"
	c, err := canary.NewHTTP(canary.Config{Type: "http", Target: target, Timeout: 5 * time.Second, Params: params, AllowInsecureSkipVerify: allowInsecure})
	if err != nil {
		t.Fatalf("NewHTTP: %v", err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return res
}

func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func TestHTTPSuccessWithTimingAndTLS(t *testing.T) {
	ca, err := crypto.GenerateCA("probectl-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert("localhost", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, caFile := tlsServer(t, certPEM, keyPEM, ca.CertPEM(), http.HandlerFunc(okHandler))

	res := runHTTP(t, srv.URL+"/health", map[string]string{"ca_file": caFile})

	if !res.Success {
		t.Fatalf("success=false err=%q", res.Error)
	}
	if res.Metrics["http.status"] != 200 {
		t.Errorf("http.status = %v, want 200", res.Metrics["http.status"])
	}
	for _, m := range []string{"http.connect.ms", "http.tls.ms", "http.ttfb.ms", "http.total.ms"} {
		if _, ok := res.Metrics[m]; !ok {
			t.Errorf("missing timing metric %s (metrics=%v)", m, res.Metrics)
		}
	}
	if res.Metrics["http.total.ms"] <= 0 {
		t.Errorf("http.total.ms = %v, want > 0", res.Metrics["http.total.ms"])
	}
	if res.Attributes["http.response.status_code"] != "200" {
		t.Errorf("status_code attr = %q", res.Attributes["http.response.status_code"])
	}
	// TLS handshake details captured for S27.
	if v := res.Attributes["tls.protocol.version"]; v != "1.3" && v != "1.2" {
		t.Errorf("tls.protocol.version = %q", v)
	}
	if res.Attributes["tls.cipher.suite"] == "" {
		t.Error("missing tls.cipher.suite")
	}
	notAfter, err := time.Parse(time.RFC3339, res.Attributes["probectl.tls.server.not_after"])
	if err != nil {
		t.Fatalf("probectl.tls.server.not_after %q: %v", res.Attributes["probectl.tls.server.not_after"], err)
	}
	if !notAfter.After(time.Now()) {
		t.Errorf("not_after %s should be in the future", notAfter)
	}
	if res.Metrics["http.tls.cert_expiry_days"] <= 0 {
		t.Errorf("cert_expiry_days = %v, want > 0", res.Metrics["http.tls.cert_expiry_days"])
	}
	if res.Attributes["network.peer.address"] != "127.0.0.1" {
		t.Errorf("network.peer.address = %q, want 127.0.0.1", res.Attributes["network.peer.address"])
	}
}

func TestHTTPServerError5xx(t *testing.T) {
	ca, _ := crypto.GenerateCA("probectl-test-ca", time.Hour)
	certPEM, keyPEM, _ := ca.IssueServerCert("localhost", []string{"127.0.0.1"}, time.Hour)
	srv, caFile := tlsServer(t, certPEM, keyPEM, ca.CertPEM(), http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))

	res := runHTTP(t, srv.URL, map[string]string{"ca_file": caFile})

	if res.Success {
		t.Error("5xx must be success=false")
	}
	if res.Metrics["http.status"] != 503 {
		t.Errorf("http.status = %v, want 503", res.Metrics["http.status"])
	}
	if res.Attributes["http.response.status_code"] != "503" {
		t.Errorf("status_code attr = %q", res.Attributes["http.response.status_code"])
	}
}

func TestHTTPSlowTimesOut(t *testing.T) {
	ca, _ := crypto.GenerateCA("probectl-test-ca", time.Hour)
	certPEM, keyPEM, _ := ca.IssueServerCert("localhost", []string{"127.0.0.1"}, time.Hour)
	srv, caFile := tlsServer(t, certPEM, keyPEM, ca.CertPEM(), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done(): // client gave up — return promptly so Close() doesn't block
		}
	}))

	c, err := canary.NewHTTP(canary.Config{Type: "http", Target: srv.URL, Timeout: 300 * time.Millisecond,
		Params: map[string]string{"allow_private_targets": "true", "ca_file": caFile}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Success {
		t.Error("a probe that exceeds its timeout must be success=false")
	}
	if res.Error == "" {
		t.Error("expected a timeout error message")
	}
	// The TLS handshake completed before the slow body, so its details are still captured.
	if res.Attributes["tls.protocol.version"] == "" {
		t.Error("expected TLS details even on a slow response")
	}
}

func TestHTTPExpiredCertCapturedAndFailed(t *testing.T) {
	ca, err := crypto.GenerateCA("probectl-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Negative TTL → the leaf's NotAfter is in the past (expired).
	certPEM, keyPEM, err := ca.IssueServerCert("localhost", []string{"127.0.0.1"}, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, caFile := tlsServer(t, certPEM, keyPEM, ca.CertPEM(), http.HandlerFunc(okHandler))

	res := runHTTP(t, srv.URL, map[string]string{"ca_file": caFile})

	if res.Success {
		t.Error("an expired certificate must fail the probe")
	}
	// Crucially, the cert details are captured even though verification failed —
	// S27 needs them (sprint watch-out: capture TLS details now).
	notAfter, err := time.Parse(time.RFC3339, res.Attributes["probectl.tls.server.not_after"])
	if err != nil {
		t.Fatalf("expected captured not_after, got %q (%v)", res.Attributes["probectl.tls.server.not_after"], err)
	}
	if notAfter.After(time.Now()) {
		t.Errorf("not_after %s should be in the past", notAfter)
	}
	if res.Metrics["http.tls.cert_expiry_days"] >= 0 {
		t.Errorf("cert_expiry_days = %v, want negative for an expired cert", res.Metrics["http.tls.cert_expiry_days"])
	}
}

func TestHTTPInsecureSkipVerifyCaptures(t *testing.T) {
	ca, _ := crypto.GenerateCA("probectl-test-ca", time.Hour)
	certPEM, keyPEM, _ := ca.IssueServerCert("localhost", []string{"127.0.0.1"}, time.Hour)
	srv, _ := tlsServer(t, certPEM, keyPEM, ca.CertPEM(), http.HandlerFunc(okHandler))

	// No ca_file: the cert is untrusted, but insecure_skip_verify lets the probe
	// succeed while still capturing the handshake details.
	res := runHTTP(t, srv.URL, map[string]string{"insecure_skip_verify": "true"})

	if !res.Success {
		t.Fatalf("insecure probe should succeed: %q", res.Error)
	}
	if res.Attributes["tls.cipher.suite"] == "" {
		t.Error("TLS details should be captured even in insecure mode")
	}
}

func TestHTTPPlainNoTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(okHandler))
	t.Cleanup(srv.Close)

	res := runHTTP(t, srv.URL+"/x", nil)

	if !res.Success || res.Metrics["http.status"] != 200 {
		t.Fatalf("plain http: success=%v status=%v err=%q", res.Success, res.Metrics["http.status"], res.Error)
	}
	if _, ok := res.Metrics["http.tls.ms"]; ok {
		t.Error("plain http must not report a TLS phase")
	}
	if _, ok := res.Attributes["tls.protocol.version"]; ok {
		t.Error("plain http must not capture TLS attributes")
	}
	if _, ok := res.Metrics["http.connect.ms"]; !ok {
		t.Error("missing http.connect.ms")
	}
}

func TestHTTPNoFollowRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/go" {
			http.Redirect(w, r, "/dest", http.StatusFound)
			return
		}
		okHandler(w, r)
	}))
	t.Cleanup(srv.Close)

	res := runHTTP(t, srv.URL+"/go", map[string]string{"follow_redirects": "false", "expect_status": "3xx"})

	if !res.Success {
		t.Fatalf("302 should match 3xx: %q", res.Error)
	}
	if res.Metrics["http.status"] != 302 {
		t.Errorf("http.status = %v, want 302 (redirect not followed)", res.Metrics["http.status"])
	}
}
