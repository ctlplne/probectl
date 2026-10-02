// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"

	"github.com/ctlplne/probectl/internal/crypto"
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

func agentKeepaliveServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	// Route key/cert generation through internal/crypto (FIPS enabler, G7-3).
	ca, err := crypto.GenerateCA("agent-keepalive-test-ca", time.Hour)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	certPEM, keyPEM, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatalf("issue server cert: %v", err)
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load server keypair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
}

// TestGRPCServerClosesIdleConnection builds a gRPC server with the agent
// transport's keepalive options (short idle) and a real client over TCP+TLS,
// and confirms the idle connection is reaped after MaxConnectionIdle (WEB-06).
func TestGRPCServerClosesIdleConnection(t *testing.T) {
	ka := defaultGRPCKeepalive()
	ka.maxConnectionIdle = 200 * time.Millisecond

	opts := append([]grpc.ServerOption{grpc.Creds(credentials.NewTLS(agentKeepaliveServerTLS(t)))}, ka.serverOptions()...)
	gs := grpc.NewServer(opts...)

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := &trackingListener{Listener: base, closes: make(chan struct{}, 4)}
	go func() { _ = gs.Serve(ln) }()
	t.Cleanup(gs.Stop)

	clientTLS := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

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
		// Server reaped the idle agent connection after MaxConnectionIdle.
	case <-time.After(3 * time.Second):
		t.Fatal("server did not disconnect the idle connection after MaxConnectionIdle")
	}
}

// TestGRPCKeepaliveDefaultsMatchSpec pins the production keepalive numbers and
// the rendered option set for the agent transport (WEB-06).
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

// TestAgentGRPCServerWiresKeepalive is a source-level pin that New() appends the
// keepalive options to the grpc.NewServer option set — the agent listener's
// grpc.NewServer call is inside New(), which needs a TLS keypair + pool to
// exercise, so this guards the wiring directly.
func TestAgentGRPCServerWiresKeepalive(t *testing.T) {
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatalf("read server.go: %v", err)
	}
	if !strings.Contains(string(src), "defaultGRPCKeepalive().serverOptions()") {
		t.Fatal("New() must append defaultGRPCKeepalive().serverOptions() to the agent gRPC server options (WEB-06)")
	}
}
