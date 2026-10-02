// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"
	"testing"
	"time"

	probectlc "github.com/ctlplne/probectl/internal/crypto"
)

// RTP-03: the BMP listener consults the registry revocation deny-list only ONCE,
// at the mTLS handshake (bmp.go handleConn, before the read loop). A BMP session
// is long-lived — a router keeps the connection open and dribbles route-
// monitoring frames for as long as its (short-lived) certificate is valid. So a
// router revoked AFTER its session was established kept publishing routing events
// on the already-open connection until the certificate expired: the operator
// believed the revocation had taken hold while the routing plane kept ingesting
// from the revoked peer. This is the BMP analog of CRY-01 (the per-RPC agent-
// transport recheck).
//
// These tests exercise the REAL session path: a persistent mTLS connection into
// BMPListener.Serve, an event published while live, then a revocation pushed into
// the SAME in-memory deny-list the listener's refresh feed keeps current
// (cmd/probectl-bmp-listener/revocations.go, via RevocationList.Replace /
// RevokeSerial), and a second frame on the SAME connection. The fix refuses that
// next frame and closes the session; pre-fix the frame was published and the
// session stayed open (guardrail §7.4/§7.12 — a revoked credential fails closed
// on every path).
func TestBMPRouterRevokedMidSessionStopsPublishing(t *testing.T) {
	h := newBMPRevokeHarness(t)
	defer h.stop()

	router := h.issue("tenant-a", "router-a")

	// --- The session is established and the router is live: it publishes. ---
	conn := h.dial(router)
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(buildBMPRouteMonitoring(
		64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", time.Now())); err != nil {
		t.Fatalf("write first frame: %v", err)
	}
	_ = waitCaptured(t, h.pub, 1)

	// --- The operator revokes the router's identity. The refresh feed installs
	// it into the SAME in-memory list the listener reads (Replace = the periodic
	// registry reload). The connection is NOT reopened — the session stays up. ---
	h.revocations.Replace(nil, []string{router.spiffe})

	// --- The NEXT frame on the SAME established connection must be refused: no
	// further events publish, and the session is closed (fail closed, RTP-03). ---
	if _, err := conn.Write(buildBMPRouteMonitoring(
		64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.114.0/24", time.Now())); err != nil {
		t.Fatalf("write post-revocation frame: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := h.pub.count(); got != 1 {
		t.Fatalf("revoked router kept publishing on its established session: got %d events, want 1 (RTP-03)", got)
	}
	assertBMPSessionClosed(t, conn)

	// --- The recheck is TARGETED, not a blanket refuse-everything: an unrelated
	// live router opening a fresh session after the revocation still publishes. ---
	other := h.issue("tenant-b", "router-b")
	otherConn := h.dial(other)
	defer func() { _ = otherConn.Close() }()
	if _, err := otherConn.Write(buildBMPRouteMonitoring(
		64512, "192.0.2.12", []uint32{64512, 64501}, "198.51.100.0/24", time.Now())); err != nil {
		t.Fatalf("write unrelated-router frame: %v", err)
	}
	_ = waitCaptured(t, h.pub, 2)
}

// Revoking by SERIAL (not identity) refuses the router mid-session too — the
// other deny-list dimension, re-checked per frame.
func TestBMPRouterRevokedMidSessionBySerialStopsPublishing(t *testing.T) {
	h := newBMPRevokeHarness(t)
	defer h.stop()

	router := h.issue("tenant-a", "router-a")
	conn := h.dial(router)
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write(buildBMPRouteMonitoring(
		64511, "192.0.2.11", []uint32{64511}, "203.0.113.0/24", time.Now())); err != nil {
		t.Fatalf("write first frame: %v", err)
	}
	_ = waitCaptured(t, h.pub, 1)

	h.revocations.RevokeSerial(router.serial)

	if _, err := conn.Write(buildBMPRouteMonitoring(
		64511, "192.0.2.11", []uint32{64511}, "203.0.114.0/24", time.Now())); err != nil {
		t.Fatalf("write post-revocation frame: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := h.pub.count(); got != 1 {
		t.Fatalf("serial-revoked router kept publishing on its established session: got %d events, want 1 (RTP-03)", got)
	}
	assertBMPSessionClosed(t, conn)
}

// bmpRevokeHarness is a running BMP listener wired to an in-memory revocation
// list, plus the CA and address needed to mint routers and open real sessions.
type bmpRevokeHarness struct {
	t           *testing.T
	ca          *probectlc.CA
	caFile      string
	dir         string
	addr        string
	pub         *capturePublisher
	revocations *probectlc.RevocationList
	cancel      func()
	errc        chan error
}

type bmpRouter struct {
	certFile string
	keyFile  string
	spiffe   string
	serial   string
}

func newBMPRevokeHarness(t *testing.T) *bmpRevokeHarness {
	t.Helper()
	ca, err := probectlc.GenerateCA("bmp-midsession-revoke-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := writePEM(t, dir, "ca.crt", ca.CertPEM())
	serverCert, serverKey, err := ca.IssueServerCert("bmp-listener", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg, err := probectlc.ServerBMPMTLSConfig(
		writePEM(t, dir, "server.crt", serverCert),
		writePEM(t, dir, "server.key", serverKey),
		caFile,
	)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}

	pub := &capturePublisher{}
	revocations := probectlc.NewRevocationList()
	listener := NewBMPListener(
		ln,
		pub,
		"bmp-test",
		discardLogger(),
		// Every registry-issued router minted by h.issue is accepted at the
		// handshake; revocation is what this test drives mid-session.
		WithBMPIssuedIdentityVerifier(allowBMPIdentity),
		WithBMPRevocationList(revocations),
	)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- listener.Serve(ctx) }()

	return &bmpRevokeHarness{
		t:           t,
		ca:          ca,
		caFile:      caFile,
		dir:         dir,
		addr:        ln.Addr().String(),
		pub:         pub,
		revocations: revocations,
		cancel:      cancel,
		errc:        errc,
	}
}

func (h *bmpRevokeHarness) issue(tenantID, routerID string) bmpRouter {
	h.t.Helper()
	spiffe := probectlc.BMPSPIFFEID(tenantID, routerID)
	certPEM, keyPEM, err := h.ca.IssueClientCert(routerID, spiffe, time.Hour)
	if err != nil {
		h.t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		h.t.Fatal("decode client certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		h.t.Fatal(err)
	}
	return bmpRouter{
		certFile: writePEM(h.t, h.dir, tenantID+"-"+routerID+".crt", certPEM),
		keyFile:  writePEM(h.t, h.dir, tenantID+"-"+routerID+".key", keyPEM),
		spiffe:   spiffe,
		serial:   leaf.SerialNumber.Text(16),
	}
}

// dial opens a persistent mTLS session into the listener. Unlike the
// connection-per-message helper, the returned connection stays open so a
// revocation can land mid-session.
func (h *bmpRevokeHarness) dial(r bmpRouter) net.Conn {
	h.t.Helper()
	cfg, err := probectlc.ClientMTLSConfig(r.certFile, r.keyFile, h.caFile)
	if err != nil {
		h.t.Fatal(err)
	}
	cfg.ServerName = "127.0.0.1"
	conn, err := tls.Dial("tcp", h.addr, cfg)
	if err != nil {
		h.t.Fatal(err)
	}
	return conn
}

func (h *bmpRevokeHarness) stop() {
	h.cancel()
	select {
	case err := <-h.errc:
		if err != nil {
			h.t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		h.t.Fatal("listener did not stop")
	}
}

// assertBMPSessionClosed proves the listener closed the revoked router's session.
// A read on the client side returns a non-timeout error (EOF / reset) once the
// server hard-closes; a timeout means the session stayed open — the RTP-03 bug.
func assertBMPSessionClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err := conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("revoked router's session stayed open: server kept reading it (RTP-03)")
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("revoked router's session stayed open: read timed out, server never closed it (RTP-03)")
	}
}
