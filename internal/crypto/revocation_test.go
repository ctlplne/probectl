// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRevocationListMatching(t *testing.T) {
	rl := NewRevocationList()
	if !rl.Empty() {
		t.Fatal("new list must be empty")
	}
	rl.RevokeSerial("0xDE:AD:BE:EF")
	rl.RevokeID("spiffe://probectl/tenant/t1/agent/a1")
	if rl.Empty() || rl.Size() != 2 {
		t.Fatalf("size = %d", rl.Size())
	}
	// Serial matching is shape-insensitive (hex, separators, case).
	if !rl.IsRevoked("deadbeef", "") {
		t.Fatal("normalized serial should match")
	}
	if rl.IsRevoked("cafef00d", "spiffe://probectl/tenant/t2/agent/b") {
		t.Fatal("unrelated cert must not be revoked")
	}
	if !rl.IsRevoked("", "spiffe://probectl/tenant/t1/agent/a1") {
		t.Fatal("id match should hold")
	}
	// Replace swaps the whole set (registry refresh).
	rl.Replace([]string{"abc"}, nil)
	if rl.IsRevoked("deadbeef", "") || !rl.IsRevoked("abc", "") {
		t.Fatal("Replace must swap the deny-list atomically")
	}
}

// U-038 acceptance: a valid, trust-domain-pinned client cert is accepted —
// until it is revoked (by serial, then independently by SPIFFE id), after
// which the handshake-time verify hook REFUSES it.
func TestRevokedClientCertRefusedAtHandshake(t *testing.T) {
	ca, err := GenerateCA("test-ca", time.Hour)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	id := AgentSPIFFEID("t1", "a1")
	certPEM, _, err := ca.IssueClientCert("agent", id, time.Hour)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	leaf := leafFromPEM(t, certPEM)
	serial := leaf.SerialNumber.Text(16)

	rl := NewRevocationList()
	guard := revocationGuard(rl, requirePinnedTrustDomain)

	// Not revoked → the pinned-trust-domain cert passes.
	if err := guard([][]byte{leaf.Raw}, nil); err != nil {
		t.Fatalf("valid cert refused: %v", err)
	}

	// Revoke by serial → refused, loudly, naming the serial.
	rl.RevokeSerial(serial)
	err = guard([][]byte{leaf.Raw}, nil)
	if err == nil || !strings.Contains(err.Error(), "REVOKED") {
		t.Fatalf("revoked-by-serial not refused: %v", err)
	}

	// Independently, revoke by SPIFFE id (covers re-issued certs).
	rl2 := NewRevocationList()
	rl2.RevokeID(id)
	if err := revocationGuard(rl2, requirePinnedTrustDomain)([][]byte{leaf.Raw}, nil); err == nil {
		t.Fatal("revoked-by-spiffe-id not refused")
	}

	// A foreign-trust-domain cert is still refused by the BASE check first
	// (revocation augments, never weakens, the pin).
	foreignPEM, _, err := ca.IssueClientCert("evil", "spiffe://evil/tenant/t/agent/a", time.Hour)
	if err != nil {
		t.Fatalf("issue foreign: %v", err)
	}
	if err := guard([][]byte{leafFromPEM(t, foreignPEM).Raw}, nil); err == nil {
		t.Fatal("foreign trust domain must still be refused")
	}
}

func TestBMPRegisteredRevocationReplaceKeepsOtherTenantHandshake(t *testing.T) {
	tenantAID := BMPSPIFFEID("tenant-a", "router-a")
	tenantBID := BMPSPIFFEID("tenant-b", "router-b")
	fixture := mtlsMaterialForSPIFFE(t, tenantAID)
	tenantALeaf := leafFromPEM(t, mustReadFile(t, fixture.clientCrt))
	tenantBLeaf := issueClientLeafWithURIs(t, fixture.ca, tenantBID)

	revocations := NewRevocationList()
	cfg, err := ServerBMPMTLSConfigRegisteredRevocable(
		fixture.serverCrt,
		fixture.serverKey,
		fixture.caFile,
		func(_ context.Context, _, _, _, _ string) (bool, error) {
			return true, nil
		},
		time.Second,
		revocations,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{tenantALeaf.Raw}, nil); err != nil {
		t.Fatalf("registered tenant-A BMP identity refused before revocation: %v", err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{tenantBLeaf.Raw}, nil); err != nil {
		t.Fatalf("registered tenant-B BMP identity refused before revocation: %v", err)
	}

	revocations.Replace(
		[]string{tenantALeaf.SerialNumber.Text(16)},
		[]string{tenantAID},
	)
	if err := cfg.VerifyPeerCertificate([][]byte{tenantALeaf.Raw}, nil); err == nil {
		t.Fatal("refreshed BMP revocation snapshot did not reject tenant A")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{tenantBLeaf.Raw}, nil); err != nil {
		t.Fatalf("tenant-A revocation affected tenant B: %v", err)
	}
}
