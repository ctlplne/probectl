// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

// D-43 S9: the eBPF collector has its own SPIFFE plane. The agent listener's
// handshake admits agent and eBPF identities, never a BMP router; the plane
// parsers do not cross.
func TestEBPFPlaneIsDistinct(t *testing.T) {
	const tenant, id = "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"
	ca, err := GenerateCA("ebpf-plane", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(spiffe string) *x509.Certificate {
		certPEM, _, err := ca.IssueClientCert(id, spiffe, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(certPEM)
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ebpf, agent, bmp := leaf(EBPFSPIFFEID(tenant, id)), leaf(AgentSPIFFEID(tenant, id)), leaf(BMPSPIFFEID(tenant, id))
	if got, err := EBPFSPIFFEIDFromCert(ebpf); err != nil || got.Plane != "ebpf" || got.TenantID != tenant || got.AgentID != id {
		t.Fatalf("eBPF parse = %+v, %v", got, err)
	}
	if _, err := SPIFFEIDFromCert(ebpf); err == nil {
		t.Fatal("an eBPF identity parsed as an agent identity")
	}
	if _, err := EBPFSPIFFEIDFromCert(agent); err == nil {
		t.Fatal("an agent identity parsed as an eBPF identity")
	}
	for name, c := range map[string]*x509.Certificate{"agent": agent, "ebpf": ebpf} {
		if err := requireAgentChannelPlane([][]byte{c.Raw}, nil); err != nil {
			t.Fatalf("agent listener refused the %s identity: %v", name, err)
		}
	}
	if err := requireAgentChannelPlane([][]byte{bmp.Raw}, nil); err == nil {
		t.Fatal("agent listener admitted a BMP router identity")
	}
	if got, err := RegisteredSPIFFEIDFromCert(ebpf); err != nil || got.Plane != "ebpf" {
		t.Fatalf("rotation/revocation cannot read the eBPF identity: %+v %v", got, err)
	}
}
