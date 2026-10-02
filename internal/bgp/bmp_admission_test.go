// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	probectlc "github.com/ctlplne/probectl/internal/crypto"
)

// ING-11: a BMP session slot used to be reserved BEFORE the mTLS + registry
// handshake, so idle/unauthenticated TCP sockets held post-auth capacity for the
// whole handshake timeout and could starve every real router; and once a session
// was established, a later revocation or the leaf's NotAfter expiry did not
// terminate it until it next sent a frame. These tests drive the REAL listener
// (recorded TLS material minted through internal/crypto) and assert: idle
// pre-auth sockets never consume the post-auth pool; per-source-IP and
// per-identity caps hold; and a revoked or expired router's LIVE, quiet session
// is torn down within one liveness refresh (docs/guardrails.md G7-4/G7-12).

// bmpTestStack is a running BMP listener over tenant-bound mTLS plus the CA and
// address needed to mint routers and open real (idle or authenticated) sessions.
type bmpTestStack struct {
	t      *testing.T
	ca     *probectlc.CA
	caFile string
	dir    string
	addr   string
	pub    *capturePublisher
	cancel context.CancelFunc
	errc   chan error
}

func startBMPTestStack(t *testing.T, opts ...BMPOption) *bmpTestStack {
	t.Helper()
	ca, err := probectlc.GenerateCA("bmp-admission-ca", time.Hour)
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
	listener := NewBMPListener(
		ln,
		pub,
		"bmp-admission",
		discardLogger(),
		append([]BMPOption{WithBMPIssuedIdentityVerifier(allowBMPIdentity)}, opts...)...,
	)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- listener.Serve(ctx) }()
	return &bmpTestStack{
		t:      t,
		ca:     ca,
		caFile: caFile,
		dir:    dir,
		addr:   ln.Addr().String(),
		pub:    pub,
		cancel: cancel,
		errc:   errc,
	}
}

func (s *bmpTestStack) issue(tenantID, routerID string, ttl time.Duration) (certFile, keyFile, spiffe string) {
	s.t.Helper()
	spiffe = probectlc.BMPSPIFFEID(tenantID, routerID)
	certPEM, keyPEM, err := s.ca.IssueClientCert(routerID, spiffe, ttl)
	if err != nil {
		s.t.Fatal(err)
	}
	certFile = writePEM(s.t, s.dir, tenantID+"-"+routerID+".crt", certPEM)
	keyFile = writePEM(s.t, s.dir, tenantID+"-"+routerID+".key", keyPEM)
	return certFile, keyFile, spiffe
}

func (s *bmpTestStack) dial(certFile, keyFile string) (net.Conn, error) {
	s.t.Helper()
	cfg, err := probectlc.ClientMTLSConfig(certFile, keyFile, s.caFile)
	if err != nil {
		s.t.Fatal(err)
	}
	cfg.ServerName = "127.0.0.1"
	return tls.Dial("tcp", s.addr, cfg)
}

func (s *bmpTestStack) stop() {
	s.cancel()
	select {
	case err := <-s.errc:
		if err != nil {
			s.t.Fatalf("serve returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		s.t.Fatal("listener did not stop")
	}
}

// TestBMPIdlePreAuthSocketsDoNotExhaustPostAuthSlots fills the listener with
// idle, unauthenticated TCP sockets and then admits one real router. Pre-fix the
// idle sockets each reserved a post-auth slot before authenticating and held it
// for the whole handshake timeout, so with a single post-auth slot they starved
// the real router. The fix keeps unauthenticated sockets in a SEPARATE pre-auth
// pool, so the post-auth slot stays free for the authenticated router.
//
// Uses only pre-existing listener symbols so the assertion itself is RED on the
// unfixed listener (idle sockets own the slot) and GREEN after the fix.
func TestBMPIdlePreAuthSocketsDoNotExhaustPostAuthSlots(t *testing.T) {
	s := startBMPTestStack(t, WithBMPMaxSessions(1))
	defer s.stop()

	const idle = 5
	for i := 0; i < idle; i++ {
		c, err := net.Dial("tcp", s.addr)
		if err != nil {
			t.Fatalf("open idle socket %d: %v", i, err)
		}
		defer func(c net.Conn) { _ = c.Close() }(c)
	}
	// Let the accept loop admit the idle sockets before the real router arrives,
	// so pre-fix they own the single post-auth slot by the time it connects.
	time.Sleep(300 * time.Millisecond)

	certFile, keyFile, _ := s.issue("tenant-a", "router-a", time.Hour)
	conn, err := s.dial(certFile, keyFile)
	if err != nil {
		// Pre-fix the real router is refused at connect because idle sockets own
		// the only post-auth slot; fall through to the publish assertion, which
		// is the clean RED.
		t.Logf("authenticated router dial failed (expected pre-fix): %v", err)
	} else {
		defer func() { _ = conn.Close() }()
		if _, werr := conn.Write(buildBMPRouteMonitoring(
			64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", time.Now())); werr != nil {
			t.Logf("authenticated router write failed: %v", werr)
		}
	}
	waitForBMPMessages(t, s.pub, 1)
}

// TestBMPMaxSessionsPerSourceCapsOneNoisySource proves one remote IP cannot hold
// more than the per-source cap of concurrent connections (ING-11).
func TestBMPMaxSessionsPerSourceCapsOneNoisySource(t *testing.T) {
	metrics := &bmpSessionMetricsCapture{}
	s := startBMPTestStack(t,
		WithBMPMaxSessionsPerSource(2),
		WithBMPSessionMetrics(metrics),
	)
	defer s.stop()

	held := make([]net.Conn, 0, 2)
	for i, routerID := range []string{"router-a", "router-b"} {
		cf, kf, _ := s.issue("tenant-a", routerID, time.Hour)
		c, err := s.dial(cf, kf)
		if err != nil {
			t.Fatalf("dial %s: %v", routerID, err)
		}
		held = append(held, c)
		prefix := "203.0.113.0/24"
		if i == 1 {
			prefix = "203.0.114.0/24"
		}
		if _, err := c.Write(buildBMPRouteMonitoring(
			uint32(64510+i), "192.0.2.1", []uint32{uint32(64510 + i)}, prefix, time.Now())); err != nil {
			t.Fatalf("write %s: %v", routerID, err)
		}
	}
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	// Both are fully admitted (they published), so localhost now holds its cap.
	waitForBMPMessages(t, s.pub, 2)

	// A third connection from the SAME source is refused at admission, before any
	// handshake work.
	cf, kf, _ := s.issue("tenant-a", "router-c", time.Hour)
	if extra, err := s.dial(cf, kf); err == nil {
		defer func() { _ = extra.Close() }()
	}
	waitForRejection(t, metrics, 1)
}

// TestBMPMaxSessionsPerIdentityCapsOneCredential proves one registered router
// identity cannot hold more than the per-identity cap of concurrent admitted
// sessions, even from under the per-source cap (ING-11).
func TestBMPMaxSessionsPerIdentityCapsOneCredential(t *testing.T) {
	metrics := &bmpSessionMetricsCapture{}
	s := startBMPTestStack(t,
		WithBMPMaxSessionsPerIdentity(2),
		WithBMPSessionMetrics(metrics),
	)
	defer s.stop()

	// One identity, reused across connections.
	cf, kf, _ := s.issue("tenant-a", "router-a", time.Hour)
	held := make([]net.Conn, 0, 2)
	for i := 0; i < 2; i++ {
		c, err := s.dial(cf, kf)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		held = append(held, c)
		prefix := "203.0.113.0/24"
		if i == 1 {
			prefix = "203.0.114.0/24"
		}
		if _, err := c.Write(buildBMPRouteMonitoring(
			64511, "192.0.2.1", []uint32{64511}, prefix, time.Now())); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	defer func() {
		for _, c := range held {
			_ = c.Close()
		}
	}()
	waitForBMPMessages(t, s.pub, 2)

	// A third session for the SAME identity is refused after authentication.
	if extra, err := s.dial(cf, kf); err == nil {
		defer func() { _ = extra.Close() }()
	}
	waitForRejection(t, metrics, 1)
}

// TestBMPRevokedRouterQuietLiveSessionTerminatedOnRefreshTick proves a router
// revoked AFTER its session is established is torn down within one liveness
// refresh even if it stays quiet — the per-frame recheck (RTP-03) never fires on
// a silent session, so the sweep is what fails closed here (ING-11).
func TestBMPRevokedRouterQuietLiveSessionTerminatedOnRefreshTick(t *testing.T) {
	revocations := probectlc.NewRevocationList()
	s := startBMPTestStack(t,
		WithBMPRevocationList(revocations),
		WithBMPLivenessRefresh(40*time.Millisecond),
	)
	defer s.stop()

	cf, kf, spiffe := s.issue("tenant-a", "router-a", time.Hour)
	conn, err := s.dial(cf, kf)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(buildBMPRouteMonitoring(
		64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", time.Now())); err != nil {
		t.Fatalf("write first frame: %v", err)
	}
	waitForBMPMessages(t, s.pub, 1)

	// Revoke the router in the SAME in-memory snapshot the refresh feed keeps
	// current (Replace = the periodic registry reload) and send NO further frame.
	revocations.Replace(nil, []string{spiffe})

	// The sweep must close the quiet, revoked session within one refresh tick.
	assertBMPSessionClosed(t, conn)
	time.Sleep(60 * time.Millisecond)
	if got := s.pub.count(); got != 1 {
		t.Fatalf("revoked router published after revocation: got %d events, want 1 (ING-11)", got)
	}
}

// TestBMPExpiredLeafQuietLiveSessionTerminatedOnRefreshTick proves a session
// whose leaf certificate expires mid-flight is torn down within one liveness
// refresh even if the router stays quiet. The listener clock is advanced past
// the leaf NotAfter deterministically; the real mTLS handshake still used the
// real clock, so the credential was valid when the session was admitted (ING-11).
func TestBMPExpiredLeafQuietLiveSessionTerminatedOnRefreshTick(t *testing.T) {
	clock := &bmpTestClock{t: time.Now()}
	s := startBMPTestStack(t,
		WithBMPLivenessRefresh(40*time.Millisecond),
		withBMPNow(clock.now),
	)
	defer s.stop()

	cf, kf, _ := s.issue("tenant-a", "router-a", time.Hour)
	conn, err := s.dial(cf, kf)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write(buildBMPRouteMonitoring(
		64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", time.Now())); err != nil {
		t.Fatalf("write first frame: %v", err)
	}
	waitForBMPMessages(t, s.pub, 1)

	// The leaf expires mid-session (advance past its NotAfter). The sweep must
	// terminate the live session within one refresh tick, with no further frame.
	clock.set(time.Now().Add(2 * time.Hour))
	assertBMPSessionClosed(t, conn)
}

// bmpTestClock is a race-safe, settable clock for the expiry sweep test.
type bmpTestClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *bmpTestClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *bmpTestClock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func waitForRejection(t *testing.T, m *bmpSessionMetricsCapture, want int64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for m.rejections.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("admission rejections = %d, want >= %d", m.rejections.Load(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
