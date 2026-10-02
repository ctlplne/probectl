// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package otlp

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
)

// trackingListener wraps a net.Listener and signals on closes whenever an
// accepted connection is closed — the server closing the transport after
// MaxConnectionIdle shows up here.
type trackingListener struct {
	net.Listener
	closes chan struct{}
}

func (l *trackingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &trackingConn{Conn: c, closes: l.closes}, nil
}

type trackingConn struct {
	net.Conn
	closes chan struct{}
	once   sync.Once
}

func (c *trackingConn) Close() error {
	c.once.Do(func() {
		select {
		case c.closes <- struct{}{}:
		default:
		}
	})
	return c.Conn.Close()
}

// TestGRPCServerClosesIdleConnection stands up the real OTLP/gRPC receiver with
// a SHORT MaxConnectionIdle, dials it with a real gRPC client over TCP+TLS, and
// confirms the server reaps the idle connection — the observable WEB-06
// acceptance (an idle connection is disconnected after MaxConnectionIdle).
func TestGRPCServerClosesIdleConnection(t *testing.T) {
	auth := NewTokenAuthenticator(map[string]string{"tok": "tenant-a"})
	sink := testSinks(SinkFunc(func(context.Context, string, *colmetricspb.ExportMetricsServiceRequest) error { return nil }))

	ka := defaultGRPCKeepalive()
	ka.maxConnectionIdle = 200 * time.Millisecond

	srv, err := newGRPCServerWithKeepalive(testServerTLS(t), auth, sink, 1<<20, nil, ka)
	if err != nil {
		t.Fatalf("newGRPCServerWithKeepalive: %v", err)
	}
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := &trackingListener{Listener: base, closes: make(chan struct{}, 4)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	clientTLS := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// grpc.NewClient is lazy: force the transport to establish, then leave it
	// idle (no RPCs) so MaxConnectionIdle governs its lifetime.
	conn.Connect()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for state := conn.GetState(); state != connectivity.Ready; state = conn.GetState() {
		if !conn.WaitForStateChange(ctx, state) {
			t.Fatalf("client never reached READY (last state=%v)", state)
		}
	}

	select {
	case <-ln.closes:
		// Server reaped the idle connection after MaxConnectionIdle.
	case <-time.After(3 * time.Second):
		t.Fatal("server did not disconnect the idle connection after MaxConnectionIdle")
	}
}

// TestGRPCKeepaliveDefaultsMatchSpec pins the production keepalive numbers and
// the rendered option set, so a future edit that loosens a bound or drops an
// option is caught (WEB-06).
func TestGRPCKeepaliveDefaultsMatchSpec(t *testing.T) {
	ka := defaultGRPCKeepalive()
	if ka.maxConnectionIdle != 5*time.Minute {
		t.Errorf("MaxConnectionIdle = %v, want 5m", ka.maxConnectionIdle)
	}
	if ka.maxConnectionAge != 30*time.Minute {
		t.Errorf("MaxConnectionAge = %v, want 30m", ka.maxConnectionAge)
	}
	if ka.maxConnectionAgeGrace != 1*time.Minute {
		t.Errorf("MaxConnectionAgeGrace = %v, want 1m", ka.maxConnectionAgeGrace)
	}
	if ka.minClientPingInterval != 30*time.Second {
		t.Errorf("keepalive MinTime = %v, want 30s", ka.minClientPingInterval)
	}
	if ka.connectionTimeout != 20*time.Second {
		t.Errorf("ConnectionTimeout = %v, want 20s", ka.connectionTimeout)
	}
	if ka.maxConcurrentStreams == 0 {
		t.Error("MaxConcurrentStreams must be a positive ceiling, got 0 (unbounded)")
	}
	if got := len(ka.serverOptions()); got != 4 {
		t.Errorf("serverOptions() = %d options, want 4 (keepalive params, enforcement policy, stream cap, connection timeout)", got)
	}
}
