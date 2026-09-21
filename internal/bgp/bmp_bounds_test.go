// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync/atomic"
	"testing"
	"time"

	probectlc "github.com/ctlplne/probectl/internal/crypto"
)

type bmpSessionMetricsCapture struct {
	timeouts   atomic.Int64
	rejections atomic.Int64
	active     atomic.Int64
}

func (m *bmpSessionMetricsCapture) SessionTimeout() {
	m.timeouts.Add(1)
}

func (m *bmpSessionMetricsCapture) SessionAdmissionRejected() {
	m.rejections.Add(1)
}

func (m *bmpSessionMetricsCapture) SetActiveSessions(active int) {
	m.active.Store(int64(active))
}

func TestBMPHandshakeStallDeadline(t *testing.T) {
	server, client := bmpTLSPipe(t)
	metrics := &bmpSessionMetricsCapture{}
	listener := NewBMPListener(nil, &capturePublisher{}, "test", discardLogger(),
		WithBMPHandshakeTimeout(30*time.Millisecond),
		WithBMPSessionMetrics(metrics),
	)
	done := make(chan error, 1)
	go func() { done <- listener.handleConn(context.Background(), server) }()

	select {
	case err := <-done:
		if !isBMPTimeout(err) {
			t.Fatalf("stalled handshake error = %v, want timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("stalled BMP handshake exceeded its deadline")
	}
	if got := metrics.timeouts.Load(); got != 1 {
		t.Fatalf("handshake timeout metric = %d, want 1", got)
	}
	_ = client.Close()
}

func TestBMPAuthenticatedFrameStallDeadline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		partial []byte
	}{
		{name: "header", partial: []byte{bmpVersion, 0}},
		{name: "payload", partial: bmpPartialPayload()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := bmpTLSPipe(t)
			metrics := &bmpSessionMetricsCapture{}
			listener := NewBMPListener(nil, &capturePublisher{}, "test", discardLogger(),
				WithBMPHandshakeTimeout(time.Second),
				WithBMPReadTimeout(30*time.Millisecond),
				WithBMPSessionMetrics(metrics),
				WithBMPIssuedIdentityVerifier(allowBMPIdentity),
			)
			done := make(chan error, 1)
			go func() { done <- listener.handleConn(context.Background(), server) }()

			if err := client.Handshake(); err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			if _, err := client.Write(tc.partial); err != nil {
				t.Fatalf("write partial %s: %v", tc.name, err)
			}
			select {
			case err := <-done:
				if !isBMPTimeout(err) {
					t.Fatalf("stalled %s error = %v, want timeout", tc.name, err)
				}
			case <-time.After(2 * time.Second):
				t.Fatalf("stalled BMP %s exceeded its rolling read deadline", tc.name)
			}
			if got := metrics.timeouts.Load(); got != 1 {
				t.Fatalf("%s timeout metric = %d, want 1", tc.name, got)
			}
			_ = client.Close()
		})
	}
}

func TestBMPSessionLimit(t *testing.T) {
	metrics := &bmpSessionMetricsCapture{}
	listener := NewBMPListener(nil, &capturePublisher{}, "test", discardLogger(),
		WithBMPMaxSessions(1),
		WithBMPSessionMetrics(metrics),
	)
	if !listener.acquireSession() {
		t.Fatal("first BMP session was not admitted")
	}
	if listener.acquireSession() {
		t.Fatal("one-past BMP session was admitted")
	}
	if got := metrics.rejections.Load(); got != 1 {
		t.Fatalf("session rejection metric = %d, want 1", got)
	}
	if got := metrics.active.Load(); got != 1 {
		t.Fatalf("active session metric = %d, want 1", got)
	}
	listener.releaseSession()
	if got := metrics.active.Load(); got != 0 {
		t.Fatalf("active session metric after release = %d, want 0", got)
	}
}

func TestBMPMessageLengthLimit(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if _, _, err := readBMPMessage(bytes.NewReader(nil)); err == nil {
			t.Fatal("empty BMP message was accepted")
		}
	})
	t.Run("truncated header", func(t *testing.T) {
		if _, _, err := readBMPMessage(bytes.NewReader([]byte{bmpVersion, 0})); err == nil {
			t.Fatal("truncated BMP header was accepted")
		}
	})
	t.Run("maximum valid", func(t *testing.T) {
		msg := make([]byte, bmpMaxMessageBytes)
		msg[0] = bmpVersion
		binary.BigEndian.PutUint32(msg[1:5], uint32(len(msg)))
		msg[5] = bmpRouteMonitoring
		msgType, payload, err := readBMPMessage(bytes.NewReader(msg))
		if err != nil {
			t.Fatalf("maximum-size BMP message: %v", err)
		}
		if msgType != bmpRouteMonitoring || len(payload) != bmpMaxMessageBytes-bmpCommonHeaderLen {
			t.Fatalf("maximum-size BMP decode = type %d payload %d", msgType, len(payload))
		}
	})
	t.Run("one past", func(t *testing.T) {
		header := make([]byte, bmpCommonHeaderLen)
		header[0] = bmpVersion
		binary.BigEndian.PutUint32(header[1:5], uint32(bmpMaxMessageBytes+1))
		if _, _, err := readBMPMessage(bytes.NewReader(header)); err == nil {
			t.Fatal("one-past BMP message was accepted")
		}
	})
}

func bmpPartialPayload() []byte {
	header := make([]byte, bmpCommonHeaderLen+1)
	header[0] = bmpVersion
	binary.BigEndian.PutUint32(header[1:5], uint32(bmpCommonHeaderLen+4))
	header[5] = bmpRouteMonitoring
	return header
}

func bmpTLSPipe(t *testing.T) (*tls.Conn, *tls.Conn) {
	t.Helper()
	ca, err := probectlc.GenerateCA("bmp-bounds-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := writePEM(t, dir, "ca.crt", ca.CertPEM())
	serverCert, serverKey, err := ca.IssueServerCert("bmp-listener", []string{"127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, clientKey, err := ca.IssueClientCert("router-a", probectlc.BMPSPIFFEID("tenant-a", "router-a"), time.Hour)
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
	clientCfg, err := probectlc.ClientMTLSConfig(
		writePEM(t, dir, "client.crt", clientCert),
		writePEM(t, dir, "client.key", clientKey),
		caFile,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.ServerName = "127.0.0.1"
	serverRaw, clientRaw := net.Pipe()
	t.Cleanup(func() {
		_ = serverRaw.Close()
		_ = clientRaw.Close()
	})
	return tls.Server(serverRaw, serverCfg), tls.Client(clientRaw, clientCfg)
}

// DPR-060: an authenticated router session is quiet most of the time. The
// read timeout must bound a frame in progress, not the wait for the next one —
// the listener used to drop every idle session after two minutes, and the
// reconnecting router re-dumped its whole table.
func TestBMPIdleAuthenticatedSessionSurvivesReadTimeout(t *testing.T) {
	server, client := bmpTLSPipe(t)
	pub := &capturePublisher{}
	listener := NewBMPListener(nil, pub, "test", discardLogger(),
		WithBMPHandshakeTimeout(time.Second),
		WithBMPReadTimeout(40*time.Millisecond),
		WithBMPIssuedIdentityVerifier(allowBMPIdentity),
	)
	done := make(chan error, 1)
	go func() { done <- listener.handleConn(context.Background(), server) }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	time.Sleep(200 * time.Millisecond) // five read timeouts of silence
	select {
	case err := <-done:
		t.Fatalf("idle authenticated session was dropped: %v", err)
	default:
	}
	if _, err := client.Write(buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", time.Now())); err != nil {
		t.Fatalf("write frame after idling: %v", err)
	}
	waitForBMPMessages(t, pub, 1)
	_ = client.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("session end = %v, want clean EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("session did not end after the peer closed")
	}
}

func TestBMPIdleTimeoutBoundsQuietSessionsWhenSet(t *testing.T) {
	server, client := bmpTLSPipe(t)
	metrics := &bmpSessionMetricsCapture{}
	listener := NewBMPListener(nil, &capturePublisher{}, "test", discardLogger(),
		WithBMPHandshakeTimeout(time.Second),
		WithBMPReadTimeout(time.Second),
		WithBMPIdleTimeout(30*time.Millisecond),
		WithBMPSessionMetrics(metrics),
		WithBMPIssuedIdentityVerifier(allowBMPIdentity),
	)
	done := make(chan error, 1)
	go func() { done <- listener.handleConn(context.Background(), server) }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	select {
	case err := <-done:
		if !isBMPTimeout(err) {
			t.Fatalf("idle session error = %v, want timeout", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("configured idle timeout did not end the quiet session")
	}
	if got := metrics.timeouts.Load(); got != 1 {
		t.Fatalf("idle timeout metric = %d, want 1", got)
	}
	_ = client.Close()
}

// DPR-060: a router that reconnects re-sends its Adj-RIB-In; an unchanged
// route from the same peer is published once per suppression window.
func TestBMPRepeatedRouteObservationIsSuppressedWithinWindow(t *testing.T) {
	seen := time.Now()
	frame := buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", seen)
	other := buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64500}, "198.51.100.0/24", seen)
	changed := buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64501}, "203.0.113.0/24", seen.Add(time.Second))
	later := buildBMPRouteMonitoring(64511, "192.0.2.11", []uint32{64511, 64500}, "203.0.113.0/24", seen.Add(2*time.Hour))

	for _, tc := range []struct {
		name   string
		window time.Duration
		frames [][]byte
		want   int
	}{
		{name: "same route twice within the window", window: time.Hour, frames: [][]byte{frame, frame}, want: 1},
		{name: "different prefix is a different observation", window: time.Hour, frames: [][]byte{frame, other}, want: 2},
		{name: "changed origin is published", window: time.Hour, frames: [][]byte{frame, changed}, want: 2},
		{name: "after the window it is published again", window: time.Hour, frames: [][]byte{frame, later}, want: 2},
		{name: "suppression disabled publishes every observation", window: 0, frames: [][]byte{frame, frame}, want: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := bmpTLSPipe(t)
			pub := &capturePublisher{}
			listener := NewBMPListener(nil, pub, "test", discardLogger(),
				WithBMPHandshakeTimeout(time.Second),
				WithBMPReadTimeout(time.Second),
				WithBMPEventSuppression(tc.window),
				WithBMPIssuedIdentityVerifier(allowBMPIdentity),
			)
			done := make(chan error, 1)
			go func() { done <- listener.handleConn(context.Background(), server) }()
			if err := client.Handshake(); err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			for _, f := range tc.frames {
				if _, err := client.Write(f); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			waitForBMPMessages(t, pub, tc.want)
			time.Sleep(50 * time.Millisecond) // a suppressed duplicate must not arrive late
			if got := pub.count(); got != tc.want {
				t.Fatalf("published = %d, want %d", got, tc.want)
			}
			_ = client.Close()
			<-done
		})
	}
}

func (c *capturePublisher) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.msgs)
}

func waitForBMPMessages(t *testing.T, pub *capturePublisher, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for pub.count() < want {
		if time.Now().After(deadline) {
			t.Fatalf("published = %d, want at least %d", pub.count(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
