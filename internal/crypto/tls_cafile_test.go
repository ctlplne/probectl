// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestHardenedHTTPClientWithCAFileTrustsOnlyTheBundle pins the private-CA
// contract for outbound integrations (enterprise LLM gateways behind a corporate
// CA): a client built from the bundle trusts a server issued by that CA, the
// default system-roots client still REFUSES it (validation is never relaxed),
// and a bundle with no certificates fails closed instead of silently falling
// back to the system roots.
func TestHardenedHTTPClientWithCAFileTrustsOnlyTheBundle(t *testing.T) {
	ca, err := GenerateCA("probectl-test-private-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert("gateway.test", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()

	dir := t.TempDir()
	caFile := filepath.Join(dir, "private-ca.pem")
	if err := os.WriteFile(caFile, ca.CertPEM(), 0o600); err != nil {
		t.Fatal(err)
	}

	trusted, err := HardenedHTTPClientWithCAFile(5*time.Second, caFile)
	if err != nil {
		t.Fatalf("build CA-file client: %v", err)
	}
	resp, err := trusted.Get(srv.URL)
	if err != nil {
		t.Fatalf("client anchored on the private CA must trust its server: %v", err)
	}
	_ = resp.Body.Close()

	if resp, err := HardenedHTTPClient(5 * time.Second).Get(srv.URL); err == nil {
		_ = resp.Body.Close()
		t.Fatal("the default system-roots client accepted a private-CA certificate; validation must stay on")
	}

	if same, err := HardenedHTTPClientWithCAFile(5*time.Second, ""); err != nil || same == nil {
		t.Fatalf("empty CA file must yield the default hardened client, got %v / %v", same, err)
	}

	empty := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(empty, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := HardenedHTTPClientWithCAFile(5*time.Second, empty); err == nil {
		t.Fatal("a CA bundle with no certificates must fail closed")
	}
}
