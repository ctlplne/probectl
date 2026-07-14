// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

// The documented hierarchy: root → intermediate → leaf SVID. The full chain
// must verify; the leaf carries EXACTLY the server-decided SPIFFE identity,
// client-auth only.
func TestAgentCAHierarchySVIDChain(t *testing.T) {
	root, err := GenerateRootCA("probectl agent root", 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := root.IssueIntermediate("probectl agent issuing", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	csr, _, err := CreateCSR("host-a")
	if err != nil {
		t.Fatal(err)
	}
	spiffe := AgentSPIFFEID("tenant-a", "agent-1")
	leafPEM, serial, err := inter.SignCSR(csr, spiffe, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if serial == nil || serial.Sign() <= 0 {
		t.Fatal("leaf must carry a positive random serial (revocation key)")
	}

	lb, _ := pem.Decode(leafPEM)
	leaf, err := x509.ParseCertificate(lb.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	// Chain verification: leaf → intermediate → root.
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root.Cert())
	inters.AddCert(inter.Cert())
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("leaf must chain to the root via the intermediate: %v", err)
	}
	// Identity binding: exactly the SPIFFE URI the SERVER chose.
	id, err := SPIFFEIDFromCert(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if id.TenantID != "tenant-a" || id.AgentID != "agent-1" {
		t.Fatalf("SVID identity = %+v, want tenant-a/agent-1", id)
	}
	// Client-auth only — an SVID must never be usable as a server cert.
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("leaf EKU = %v, want client-auth only", leaf.ExtKeyUsage)
	}
	if leaf.IsCA {
		t.Fatal("leaf must not be a CA")
	}
}

// The intermediate cannot mint further CAs (MaxPathLenZero): a leaf signed by
// a rogue sub-CA under the intermediate must fail chain verification.
func TestAgentCAIntermediateCannotDelegate(t *testing.T) {
	root, _ := GenerateRootCA("root", time.Hour)
	inter, _ := root.IssueIntermediate("issuing", time.Hour)
	rogue, err := inter.IssueIntermediate("rogue", time.Hour)
	if err != nil {
		t.Fatal(err) // creation succeeds locally; the CHAIN must refuse it
	}
	csr, _, _ := CreateCSR("x")
	leafPEM, _, err := rogue.SignCSR(csr, AgentSPIFFEID("t", "a"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	lb, _ := pem.Decode(leafPEM)
	leaf, _ := x509.ParseCertificate(lb.Bytes)
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(root.Cert())
	inters.AddCert(inter.Cert())
	inters.AddCert(rogue.Cert())
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("a leaf under a rogue sub-CA must NOT verify (MaxPathLen)")
	}
}

// SignCSR takes ONLY the public key from the CSR: a hostile CSR cannot
// request its own identity, and a garbage/foreign-signed CSR is refused.
func TestSignCSRServerControlsIdentity(t *testing.T) {
	root, _ := GenerateRootCA("root", time.Hour)
	inter, _ := root.IssueIntermediate("issuing", time.Hour)

	if _, _, err := inter.SignCSR([]byte("not a csr"), AgentSPIFFEID("t", "a"), time.Hour); err == nil {
		t.Fatal("malformed CSR must be refused")
	}
	if _, _, err := inter.SignCSR([]byte("-----BEGIN CERTIFICATE REQUEST-----\nZm9v\n-----END CERTIFICATE REQUEST-----\n"),
		AgentSPIFFEID("t", "a"), time.Hour); err == nil {
		t.Fatal("garbage CSR must be refused")
	}
	csr, _, _ := CreateCSR("host")
	if _, _, err := inter.SignCSR(csr, "https://not-spiffe.example", time.Hour); err == nil {
		t.Fatal("non-spiffe URI must be refused")
	}
}

// Round trip: the sealed-at-rest intermediate reloads and keeps issuing.
func TestAgentCASerializationRoundTrip(t *testing.T) {
	root, _ := GenerateRootCA("root", time.Hour)
	inter, _ := root.IssueIntermediate("issuing", time.Hour)
	keyPEM, err := inter.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	re, err := LoadCA(inter.CertPEM(), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	csr, _, _ := CreateCSR("h")
	if _, _, err := re.SignCSR(csr, AgentSPIFFEID("t", "a"), time.Hour); err != nil {
		t.Fatalf("reloaded intermediate must issue: %v", err)
	}
	if _, err := LoadCA([]byte("junk"), keyPEM); err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("junk cert PEM must be refused, got %v", err)
	}
}
