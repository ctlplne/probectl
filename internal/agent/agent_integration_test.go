//go:build integration

package agent_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/netctl/internal/agent"
	"github.com/imfeelingtheagi/netctl/internal/agenttransport"
	"github.com/imfeelingtheagi/netctl/internal/canary"
	"github.com/imfeelingtheagi/netctl/internal/crypto"
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
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// TestAgentEndToEnd proves the S5 Done-when through the real runtime: the agent
// registers over mTLS, runs the no-op canary on schedule, and the buffered
// results drain to the control plane.
func TestAgentEndToEnd(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	log := logging.New(io.Discard, "error", "json")

	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ca, err := crypto.GenerateCA("netctl-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := write("ca.crt", ca.CertPEM())
	sc, sk, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	srv, err := agenttransport.New(write("server.crt", sc), write("server.key", sk), caFile, pool, log)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, stopSrv := context.WithCancel(ctx)
	srvDone := make(chan struct{})
	go func() { _ = srv.ServeListener(srvCtx, ln); close(srvDone) }()
	defer func() { stopSrv(); <-srvDone }()

	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("agent-e2e-%d", time.Now().UnixNano()), "Agent E2E")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	agentID := newUUID(t)
	cc, ck, err := ca.IssueClientCert(agentID, crypto.AgentSPIFFEID(tn.ID, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &agent.Config{
		ControlPlane: agent.ControlPlaneConfig{GRPCAddr: ln.Addr().String()},
		TLS: agent.TLSConfig{
			CertFile: write("client.crt", cc), KeyFile: write("client.key", ck),
			CAFile: caFile, ServerName: "localhost",
		},
		Agent:    agent.Meta{Hostname: "e2e-host", Capabilities: []string{"noop"}, HeartbeatInterval: agent.Duration(time.Second)},
		Buffer:   agent.BufferConfig{Dir: filepath.Join(dir, "buffer"), MaxRecords: 1000},
		Canaries: []agent.CanaryConfig{{Type: "noop", Interval: agent.Duration(50 * time.Millisecond)}},
	}
	reg := canary.NewRegistry()
	reg.Register("noop", canary.NewNoop)
	a, err := agent.New(cfg, reg, log)
	if err != nil {
		t.Fatalf("new agent: %v", err)
	}

	agentCtx, stopAgent := context.WithCancel(ctx)
	agentDone := make(chan struct{})
	go func() { _ = a.Run(agentCtx); close(agentDone) }()
	defer func() { stopAgent(); <-agentDone }()

	online := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		var got *store.Agent
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tn.ID)), pool, func(ctx context.Context, s tenancy.Scope) error {
			a2, e := (store.Agents{}).Get(ctx, s, agentID)
			got = a2
			return e
		})
		if err == nil && got.Status == "online" && got.Hostname == "e2e-host" {
			online = true
		}
		if online && srv.AcceptedResults() > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !online {
		t.Fatal("agent did not register online")
	}
	if srv.AcceptedResults() == 0 {
		t.Fatal("no results were forwarded to the control plane")
	}
}
