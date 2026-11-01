// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The evidence credential enters the existing agent listener but is never
// interpreted as an agent, eBPF collector or BMP router identity.
func TestEntityEvidenceSPIFFEPlaneIsDistinct(t *testing.T) {
	const tenant, agent = "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"
	ca, err := GenerateCA("entity-plane", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	makeLeaf := func(uri string) *x509.Certificate {
		t.Helper()
		certPEM, _, err := ca.IssueClientCert(agent, uri, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(certPEM)
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	uri := EntitySPIFFEID(tenant, agent)
	identity, err := ParseEntitySPIFFEID(uri)
	if err != nil || identity.TenantID != tenant || identity.AgentID != agent || identity.Plane != "entity" {
		t.Fatalf("evidence URI = %+v, %v", identity, err)
	}
	entityLeaf := makeLeaf(uri)
	if got, err := EntitySPIFFEIDFromCert(entityLeaf); err != nil || got != identity {
		t.Fatalf("evidence certificate = %+v, %v", got, err)
	}
	if got, err := RegisteredSPIFFEIDFromCert(entityLeaf); err != nil || got != identity {
		t.Fatalf("rotation/revocation cannot read evidence certificate: %+v, %v", got, err)
	}
	if err := requireAgentChannelPlane([][]byte{entityLeaf.Raw}, nil); err != nil {
		t.Fatalf("agent listener refused evidence credential: %v", err)
	}
	if err := requireBMPTrustDomain([][]byte{entityLeaf.Raw}, nil); err == nil {
		t.Fatal("BMP listener accepted evidence credential")
	}
	if _, err := SPIFFEIDFromCert(entityLeaf); err == nil {
		t.Fatal("agent parser accepted evidence credential")
	}
	if _, err := EBPFSPIFFEIDFromCert(entityLeaf); err == nil {
		t.Fatal("eBPF parser accepted evidence credential")
	}
	for _, uri := range []string{AgentSPIFFEID(tenant, agent),
		EBPFSPIFFEID(tenant, agent), BMPSPIFFEID(tenant, agent)} {
		if _, err := EntitySPIFFEIDFromCert(makeLeaf(uri)); err == nil {
			t.Fatalf("evidence parser accepted another plane: %s", uri)
		}
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: entityLeaf.Raw})
	path := filepath.Join(t.TempDir(), "entity.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := EntitySPIFFEIDFromCertFile(path); err != nil || got != identity {
		t.Fatalf("evidence file identity = %+v, %v", got, err)
	}
}
