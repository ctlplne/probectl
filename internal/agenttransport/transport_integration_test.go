//go:build integration

package agenttransport_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/imfeelingtheagi/netctl/internal/agenttransport"
	"github.com/imfeelingtheagi/netctl/internal/bus"
	"github.com/imfeelingtheagi/netctl/internal/crypto"
	agentv1 "github.com/imfeelingtheagi/netctl/internal/gen/netctl/agent/v1"
	"github.com/imfeelingtheagi/netctl/internal/logging"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/store/migrate"
	"github.com/imfeelingtheagi/netctl/internal/tenancy"
	"github.com/imfeelingtheagi/netctl/migrations"
)

func dsn() string {
	if v := os.Getenv("NETCTL_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://netctl@localhost:5432/postgres?sslmode=disable"
}

func setup(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Skipf("no database available: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}
	return pool
}

func newUUID(t *testing.T) string {
	t.Helper()
	b, err := crypto.Random(16)
	if err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

type testServer struct {
	addr   string
	caFile string
	ca     *crypto.CA
}

func writeTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func startTestServer(ctx context.Context, t *testing.T, pool *pgxpool.Pool, opts ...func(*agenttransport.Server)) testServer {
	t.Helper()
	dir := t.TempDir()
	ca, err := crypto.GenerateCA("netctl-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := writeTemp(t, dir, "ca.crt", ca.CertPEM())
	sc, sk, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := agenttransport.New(
		writeTemp(t, dir, "server.crt", sc), writeTemp(t, dir, "server.key", sk), caFile,
		pool, bus.NewMemory(), nil, logging.New(io.Discard, "error", "json"))
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	for _, opt := range opts {
		opt(srv)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = srv.ServeListener(srvCtx, ln); close(done) }()
	t.Cleanup(func() { stop(); <-done })
	return testServer{addr: ln.Addr().String(), caFile: caFile, ca: ca}
}

// TestAgentRegistersOverMTLS proves the S4 Done-when: a stub client registers,
// heartbeats, and exchanges config/results over mTLS, and the registration
// persists — tenant-attributed from the client certificate's SPIFFE id.
func TestAgentRegistersOverMTLS(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	ts := startTestServer(ctx, t, pool)

	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("agent-%d", time.Now().UnixNano()), "Agent Tenant")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	agentID := newUUID(t)
	spiffe := crypto.AgentSPIFFEID(tn.ID, agentID)

	dir := t.TempDir()
	cc, ck, err := ts.ca.IssueClientCert(agentID, spiffe, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := crypto.ClientMTLSConfig(
		writeTemp(t, dir, "client.crt", cc), writeTemp(t, dir, "client.key", ck), ts.caFile)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.ServerName = "localhost"

	conn, err := grpc.NewClient(ts.addr, grpc.WithTransportCredentials(credentials.NewTLS(clientCfg)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	client := agentv1.NewAgentServiceClient(conn)

	rpcCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	resp, err := client.Register(rpcCtx, &agentv1.RegisterRequest{
		Hostname: "host-1", AgentVersion: "0.0.0-dev", Capabilities: []string{"icmp"},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.GetAgentId() != agentID || resp.GetTenantId() != tn.ID {
		t.Errorf("register identity = %s/%s, want %s/%s", resp.GetAgentId(), resp.GetTenantId(), agentID, tn.ID)
	}

	if att, err := client.Attest(rpcCtx, &agentv1.AttestRequest{Nonce: []byte("n")}); err != nil || !att.GetOk() {
		t.Fatalf("attest: %v / %+v", err, att)
	}
	if _, err := client.Heartbeat(rpcCtx, &agentv1.HeartbeatRequest{AgentId: agentID}); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}

	scCtx, scCancel := context.WithCancel(ctx)
	cs, err := client.StreamConfig(scCtx, &agentv1.StreamConfigRequest{})
	if err != nil {
		t.Fatalf("stream config: %v", err)
	}
	if _, err := cs.Recv(); err != nil {
		t.Fatalf("config recv: %v", err)
	}
	scCancel()

	rs, err := client.StreamResults(rpcCtx)
	if err != nil {
		t.Fatalf("stream results: %v", err)
	}
	for i := 0; i < 2; i++ {
		if err := rs.Send(&agentv1.StreamResultsRequest{Type: "icmp"}); err != nil {
			t.Fatalf("send result: %v", err)
		}
	}
	ack, err := rs.CloseAndRecv()
	if err != nil {
		t.Fatalf("results ack: %v", err)
	}
	if ack.GetAccepted() != 2 {
		t.Errorf("accepted = %d, want 2", ack.GetAccepted())
	}

	var got *store.Agent
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tn.ID)), pool, func(ctx context.Context, s tenancy.Scope) error {
		a, e := (store.Agents{}).Get(ctx, s, agentID)
		got = a
		return e
	})
	if err != nil {
		t.Fatalf("get agent: %v", err)
	}
	if got.TenantID != tn.ID || got.Status != "online" || got.Hostname != "host-1" || got.SPIFFEID != spiffe {
		t.Errorf("persisted agent = %+v", got)
	}
}

// TestRejectsNonMTLS asserts a client that presents no client certificate is
// rejected by the transport.
func TestRejectsNonMTLS(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	ts := startTestServer(ctx, t, pool)

	caPool, err := crypto.LoadCertPool(ts.caFile)
	if err != nil {
		t.Fatal(err)
	}
	// Verifies the server but presents no client certificate.
	cfg := &tls.Config{RootCAs: caPool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	conn, err := grpc.NewClient(ts.addr, grpc.WithTransportCredentials(credentials.NewTLS(cfg)))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer conn.Close()

	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := agentv1.NewAgentServiceClient(conn).Register(rpcCtx, &agentv1.RegisterRequest{Hostname: "x"}); err == nil {
		t.Error("server must reject a non-mTLS client (no client certificate)")
	}
}
