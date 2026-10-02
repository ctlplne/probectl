// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

// CRY-01: mTLS consults the registry deny-list only ONCE, at the handshake
// (crypto.revocationGuard, U-038). The agent lane is a long-lived bidirectional
// stream, so an agent revoked AFTER its stream was established kept attesting,
// heart-beating and streaming results on the already-open connection until its
// short-lived certificate expired — the operator believed the revocation had
// taken hold while the fleet kept reporting the agent ready. This exercises the
// REAL server wiring: the deny-list the handlers read is the SAME pointer the
// control plane feeds via Server.RevocationList() (the periodic reload / the
// immediate operator push). Every RPC re-reads it, so the NEXT
// Attest/Heartbeat/StreamResults after revocation is refused — within one
// refresh interval, fail closed (guardrail §7.4/§7.12).
func TestAgentRevokedMidStreamRefusedOnNextCall(t *testing.T) {
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("revoke-recheck-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.IssueServerCert("control", []string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// The real server, built exactly as the control plane builds it: New wires
	// the shared deny-list into both the TLS config and the handlers.
	srv, err := New(
		writeFile(t, dir, "srv.crt", srvCert),
		writeFile(t, dir, "srv.key", srvKey),
		writeFile(t, dir, "ca.crt", ca.CertPEM()),
		nil, nil, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svc := srv.svc
	// Isolate CRY-01 from two orthogonal gates that are tested elsewhere and do
	// not bear on revocation: the stream freshness/replay check (freshness_test.go)
	// and the DB heartbeat write. Both exist on the real server; nil-ing freshness
	// skips the envelope gate and an in-memory batcher keeps Heartbeat off the DB
	// (record() touches only memory; run() is never started, so the nil pool is
	// never used). The revocation recheck under test is untouched by either.
	svc.freshness = nil
	svc.hb = newHeartbeatBatcher(nil, discardLogger(), time.Minute)

	const tenant, agent = "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	spiffeID := crypto.AgentSPIFFEID(tenant, agent)
	certPEM, _, err := ca.IssueClientCert(agent, spiffeID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafFromPEM(t, certPEM)
	// A fake live principal: the peer context an established mTLS stream carries.
	ctx := peerContextForLeaf(leaf)

	// --- The stream is open and the agent is live: every lane accepts it. ---
	if _, err := svc.Attest(ctx, &agentv1.AttestRequest{}); err != nil {
		t.Fatalf("live agent Attest refused: %v", err)
	}
	if _, err := svc.Heartbeat(ctx, &agentv1.HeartbeatRequest{}); err != nil {
		t.Fatalf("live agent Heartbeat refused: %v", err)
	}
	if err := svc.StreamResults(&streamResultsTestStream{ctx: ctx}); err != nil {
		t.Fatalf("live agent StreamResults refused: %v", err)
	}

	// --- The operator revokes the agent. The control plane feeds the SAME
	// deny-list (Replace = the periodic registry reload; serial AND identity).
	// The connection is NOT reopened — the stream stays up. ---
	srv.RevocationList().Replace([]string{leaf.SerialNumber.Text(16)}, []string{spiffeID})

	// --- The NEXT message on the SAME connection must be refused on every lane,
	// fail closed, naming the cause. ---
	t.Run("Attest", func(t *testing.T) {
		_, err := svc.Attest(ctx, &agentv1.AttestRequest{})
		assertRevoked(t, err)
	})
	t.Run("Heartbeat", func(t *testing.T) {
		_, err := svc.Heartbeat(ctx, &agentv1.HeartbeatRequest{})
		assertRevoked(t, err)
	})
	t.Run("StreamResults", func(t *testing.T) {
		err := svc.StreamResults(&streamResultsTestStream{ctx: ctx})
		assertRevoked(t, err)
	})

	// --- The recheck is TARGETED, not a blanket refuse-everything: an unrelated
	// live agent on the same server still attests after the revocation. ---
	otherPEM, _, err := ca.IssueClientCert("agent-ok", crypto.AgentSPIFFEID(tenant, "agent-ok"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Attest(peerContextForLeaf(leafFromPEM(t, otherPEM)), &agentv1.AttestRequest{}); err != nil {
		t.Fatalf("an unrelated live agent was refused after a different agent's revocation: %v", err)
	}
}

// Revoking the SPIFFE IDENTITY (not a specific serial) refuses the agent on its
// next call too — the no-resurrection dimension, re-checked per RPC.
func TestAgentRevokedByIdentityRefusedOnNextCall(t *testing.T) {
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("revoke-id-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvCert, srvKey, err := ca.IssueServerCert("control", []string{"localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := New(
		writeFile(t, dir, "srv.crt", srvCert),
		writeFile(t, dir, "srv.key", srvKey),
		writeFile(t, dir, "ca.crt", ca.CertPEM()),
		nil, nil, nil, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const tenant, agent = "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444"
	spiffeID := crypto.AgentSPIFFEID(tenant, agent)
	certPEM, _, err := ca.IssueClientCert(agent, spiffeID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx := peerContextForLeaf(leafFromPEM(t, certPEM))

	if _, err := srv.svc.Attest(ctx, &agentv1.AttestRequest{}); err != nil {
		t.Fatalf("live agent Attest refused: %v", err)
	}
	srv.RevocationList().RevokeID(spiffeID)
	_, err = srv.svc.Attest(ctx, &agentv1.AttestRequest{})
	assertRevoked(t, err)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func peerContextForLeaf(leaf *x509.Certificate) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}},
	})
}

func assertRevoked(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("a revoked agent was still accepted on an established stream (CRY-01)")
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Fatalf("revoked-agent refusal code = %v, want Unauthenticated", code)
	}
	if !strings.Contains(err.Error(), "REVOKED") {
		t.Fatalf("the refusal must name the cause, got: %v", err)
	}
}
