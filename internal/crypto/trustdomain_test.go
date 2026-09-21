// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"
)

// U-011: a syntactically perfect agent SPIFFE ID under a FOREIGN trust domain
// must never parse into a probectl identity.
func TestParseSPIFFEIDRejectsForeignTrustDomain(t *testing.T) {
	foreign := []string{
		"spiffe://evil/tenant/t1/agent/a1",
		"spiffe://probectl.attacker.example/tenant/t1/agent/a1",
		"spiffe://PROBECTL/tenant/t1/agent/a1", // case is significant in trust domains
	}
	for _, uri := range foreign {
		if _, err := ParseSPIFFEID(uri); err == nil {
			t.Errorf("ParseSPIFFEID(%q) accepted a foreign trust domain", uri)
		} else if !strings.Contains(err.Error(), "trust domain") {
			t.Errorf("ParseSPIFFEID(%q): want trust-domain rejection, got %v", uri, err)
		}
	}
	if _, err := ParseSPIFFEID("spiffe://probectl/tenant/t1/agent/a1"); err != nil {
		t.Fatalf("pinned-domain id must parse: %v", err)
	}
}

func leafFromPEM(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("no PEM block")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}

// U-011 acceptance test: a certificate carrying a foreign-trust-domain SPIFFE
// SVID — even one issued by a CA the server trusts — is refused on every
// derivation/verify path.
func TestForeignTrustDomainCertIsRefused(t *testing.T) {
	ca, err := GenerateCA("test-ca", time.Hour)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}

	foreignPEM, _, err := ca.IssueClientCert("foreign-agent",
		"spiffe://evil/tenant/t1/agent/a1", time.Hour)
	if err != nil {
		t.Fatalf("issue foreign: %v", err)
	}
	foreignLeaf := leafFromPEM(t, foreignPEM)

	// Identity derivation refuses it (the server's tenant-binding path).
	if _, err := SPIFFEIDFromCert(foreignLeaf); err == nil {
		t.Fatal("SPIFFEIDFromCert accepted a foreign trust domain")
	}

	// The handshake-time hook on the server mTLS config refuses it too.
	if err := requirePinnedTrustDomain([][]byte{foreignLeaf.Raw}, nil); err == nil {
		t.Fatal("requirePinnedTrustDomain accepted a foreign trust domain")
	}

	// And the pinned domain passes both.
	okPEM, _, err := ca.IssueClientCert("agent",
		AgentSPIFFEID("t1", "a1"), time.Hour)
	if err != nil {
		t.Fatalf("issue pinned: %v", err)
	}
	okLeaf := leafFromPEM(t, okPEM)
	id, err := SPIFFEIDFromCert(okLeaf)
	if err != nil {
		t.Fatalf("pinned cert refused: %v", err)
	}
	if id.TenantID != "t1" || id.AgentID != "a1" || id.TrustDomain != TrustDomain {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if err := requirePinnedTrustDomain([][]byte{okLeaf.Raw}, nil); err != nil {
		t.Fatalf("pinned cert failed the handshake hook: %v", err)
	}
}

// The server mTLS configs carry the handshake-time verifier.
func TestServerMTLSConfigsPinTrustDomain(t *testing.T) {
	ca, err := GenerateCA("test-ca", time.Hour)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert("control", []string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatalf("issue server: %v", err)
	}
	dir := t.TempDir()
	certFile, keyFile, caFile := dir+"/tls.crt", dir+"/tls.key", dir+"/ca.crt"
	for f, b := range map[string][]byte{certFile: certPEM, keyFile: keyPEM, caFile: ca.CertPEM()} {
		if err := os.WriteFile(f, b, 0o600); err != nil {
			t.Fatalf("write %s: %v", f, err)
		}
	}

	cfg, err := ServerMTLSConfig(certFile, keyFile, caFile)
	if err != nil {
		t.Fatalf("ServerMTLSConfig: %v", err)
	}
	if cfg.VerifyPeerCertificate == nil || cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatal("ServerMTLSConfig must require clients and pin the trust domain")
	}
}
