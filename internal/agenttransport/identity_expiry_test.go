// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package agenttransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/ctlplne/probectl/internal/crypto"
)

// DPR-175: the agent lane is a long-lived stream and TLS authenticates it once,
// at the handshake. An SVID that expires mid-stream was accepted for as long as
// the connection lasted — measured on the lab as 8.5 hours of heartbeats after
// expiry, with the fleet view reporting the agent ready throughout. Every call
// must re-read the expiry of the certificate it is authenticated by.
func TestIdentityFromContextRefusesAnExpiredCertificateMidStream(t *testing.T) {
	ca, err := crypto.GenerateCA("expiry-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	const tenant, agent = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	// A SHORT-lived identity, exactly as enrolment issues them.
	certPEM, _, err := ca.IssueClientCert(agent, crypto.AgentSPIFFEID(tenant, agent), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafFromPEM(t, certPEM)
	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}},
	})

	// While it is valid the identity resolves, so the check cannot pass by
	// refusing everything.
	id, err := identityFromContext(ctx)
	if err != nil {
		t.Fatalf("a valid identity was refused: %v", err)
	}
	if id.TenantID != tenant || id.AgentID != agent {
		t.Fatalf("identity mismatch: got %s/%s", id.TenantID, id.AgentID)
	}

	// The stream is still open; only the clock moves past NotAfter.
	restore := now
	now = func() time.Time { return leaf.NotAfter.Add(time.Second) }
	t.Cleanup(func() { now = restore })

	if _, err = identityFromContext(ctx); err == nil {
		t.Fatal("an expired identity was still accepted on an established stream")
	}
	if !strings.Contains(err.Error(), "expired") || !strings.Contains(err.Error(), "rotate") {
		t.Fatalf("the refusal must name the cause and the fix, got: %v", err)
	}

	// One second before expiry it is still good: the boundary is NotAfter, not
	// a guess at how much clock skew to tolerate.
	now = func() time.Time { return leaf.NotAfter.Add(-time.Second) }
	if _, err := identityFromContext(ctx); err != nil {
		t.Fatalf("an identity one second inside its lifetime was refused: %v", err)
	}
}
