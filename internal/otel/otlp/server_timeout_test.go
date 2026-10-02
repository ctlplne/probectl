// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
)

// TestOTLPHTTPServerTimeoutsNonZero is the required minimum (WEB-05): the
// constructed OTLP/HTTP server must set every connection timeout to a non-zero
// value. With only ReadHeaderTimeout set, a slow or idle unauthenticated client
// can hold a connection open indefinitely. RED on the pre-fix server (the other
// three timeouts are zero), GREEN after.
func TestOTLPHTTPServerTimeoutsNonZero(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	sink := testSinks(SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error { return nil }))
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	// Defaults: a zero-valued config must still yield non-zero timeouts.
	s, err := NewServer(ServerConfig{HTTPAddr: "127.0.0.1:0"}, tlsCfg, auth, sink, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv := s.newHTTPServer(http.NewServeMux())

	if srv.ReadHeaderTimeout <= 0 {
		t.Errorf("ReadHeaderTimeout must be > 0, got %v", srv.ReadHeaderTimeout)
	}
	if srv.ReadTimeout <= 0 {
		t.Errorf("ReadTimeout must be > 0 (bounds a slow body), got %v", srv.ReadTimeout)
	}
	if srv.WriteTimeout <= 0 {
		t.Errorf("WriteTimeout must be > 0, got %v", srv.WriteTimeout)
	}
	if srv.IdleTimeout <= 0 {
		t.Errorf("IdleTimeout must be > 0 (bounds idle keep-alive), got %v", srv.IdleTimeout)
	}

	// A legitimate large-but-timely OTLP upload must not be cut off: ReadTimeout
	// is comfortably longer than ReadHeaderTimeout.
	if srv.ReadTimeout <= srv.ReadHeaderTimeout {
		t.Errorf("ReadTimeout (%v) should exceed ReadHeaderTimeout (%v)", srv.ReadTimeout, srv.ReadHeaderTimeout)
	}

	// Explicit config values are honored (configurable, not hard-wired).
	s2, err := NewServer(ServerConfig{
		HTTPAddr:          "127.0.0.1:0",
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       7 * time.Second,
		WriteTimeout:      11 * time.Second,
		IdleTimeout:       13 * time.Second,
	}, tlsCfg, auth, sink, nil)
	if err != nil {
		t.Fatalf("NewServer (configured): %v", err)
	}
	srv2 := s2.newHTTPServer(http.NewServeMux())
	for _, tc := range []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"ReadHeaderTimeout", srv2.ReadHeaderTimeout, 3 * time.Second},
		{"ReadTimeout", srv2.ReadTimeout, 7 * time.Second},
		{"WriteTimeout", srv2.WriteTimeout, 11 * time.Second},
		{"IdleTimeout", srv2.IdleTimeout, 13 * time.Second},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %v, want %v", tc.name, tc.got, tc.want)
		}
	}
}

// TestOTLPHTTPServerClosesSlowAndIdleClients is the behavioral proof: driving
// the real server object (the one Run uses) with short timeouts, a connection
// held idle after a completed request, and one that trickles its body, are both
// closed by the server within the configured timeout — the server acts instead
// of waiting forever. With the pre-fix zero timeouts the server would never act
// and the probe read would block until the generous client deadline.
func TestOTLPHTTPServerClosesSlowAndIdleClients(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	sink := testSinks(SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error { return nil }))

	s, err := NewServer(ServerConfig{
		HTTPAddr:          "127.0.0.1:0",
		ReadHeaderTimeout: 300 * time.Millisecond,
		ReadTimeout:       400 * time.Millisecond,
		WriteTimeout:      400 * time.Millisecond,
		IdleTimeout:       300 * time.Millisecond,
	}, &tls.Config{MinVersion: tls.VersionTLS12}, auth, sink, nil)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/metrics", MetricsHTTPHandlerWithFreshness(auth, sink.Metrics, int64(s.cfg.MaxRecvBytes), s.cfg.Freshness))
	httpSrv := s.newHTTPServer(mux)

	// Serve over a plaintext listener: the connection-timeout logic is
	// transport-agnostic, which keeps the test off a TLS cert.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = httpSrv.Serve(lis) }()
	t.Cleanup(func() { _ = httpSrv.Close() })
	addr := lis.Addr().String()

	// probeActs reports whether a read on conn returns (data, EOF, or any
	// non-timeout error) within wait — i.e. the server acted on the connection.
	// A client-side read timeout means the server left it hanging.
	probeActs := func(t *testing.T, conn net.Conn, wait time.Duration) bool {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(wait)); err != nil {
			t.Fatalf("set read deadline: %v", err)
		}
		buf := make([]byte, 256)
		_, err := conn.Read(buf)
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return false // nothing happened within the window → server hung
		}
		return true // data / EOF / reset → server acted
	}

	t.Run("idle keep-alive", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		// One complete request so the connection becomes an idle keep-alive one.
		req := "POST /v1/metrics HTTP/1.1\r\n" +
			"Host: probectl.local\r\n" +
			"Authorization: Bearer tok\r\n" +
			"Content-Type: application/x-protobuf\r\n" +
			"Content-Length: 0\r\n\r\n"
		if _, err := conn.Write([]byte(req)); err != nil {
			t.Fatalf("write request: %v", err)
		}
		if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatalf("set deadline: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatalf("read first response: %v", err)
		}
		_ = resp.Body.Close()

		// Now hold the connection idle: the server must close it ~IdleTimeout
		// later, well within this generous window.
		if !probeActs(t, conn, 4*time.Second) {
			t.Error("idle keep-alive connection was not closed within the window (IdleTimeout not enforced)")
		}
	})

	t.Run("slow body", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.Close()

		// Announce a large body, then trickle a single byte and stall. The
		// server reads under ReadTimeout and must close rather than wait.
		head := "POST /v1/metrics HTTP/1.1\r\n" +
			"Host: probectl.local\r\n" +
			"Authorization: Bearer tok\r\n" +
			"Content-Type: application/x-protobuf\r\n" +
			fmt.Sprintf("Content-Length: %d\r\n\r\n", 1<<20)
		if _, err := conn.Write([]byte(head)); err != nil {
			t.Fatalf("write head: %v", err)
		}
		if _, err := conn.Write([]byte{0x00}); err != nil && !strings.Contains(err.Error(), "broken pipe") {
			t.Fatalf("write trickle: %v", err)
		}

		if !probeActs(t, conn, 4*time.Second) {
			t.Error("slow-body connection was not closed within the window (ReadTimeout not enforced)")
		}
	})
}
