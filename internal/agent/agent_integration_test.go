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
	"github.com/imfeelingtheagi/netctl/internal/bus"
	"github.com/imfeelingtheagi/netctl/internal/canary"
	"github.com/imfeelingtheagi/netctl/internal/crypto"
	"github.com/imfeelingtheagi/netctl/internal/logging"
	"github.com/imfeelingtheagi/netctl/internal/pipeline"
	"github.com/imfeelingtheagi/netctl/internal/store"
	"github.com/imfeelingtheagi/netctl/internal/store/migrate"
	"github.com/imfeelingtheagi/netctl/internal/store/tsdb"
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

	// Result pipeline: the transport publishes to an in-memory bus that a
	// pipeline consumer drains into an in-memory TSDB, proving the full S6 path
	// agent -> gRPC -> bus -> consumer -> TSDB end to end.
	mbus := bus.NewMemory()
	mtsdb := tsdb.NewMemory()
	consumerCtx, stopConsumer := context.WithCancel(ctx)
	consumerDone := make(chan struct{})
	go func() { _ = pipeline.NewConsumer(mbus, mtsdb, "e2e", log).Run(consumerCtx); close(consumerDone) }()
	defer func() { stopConsumer(); <-consumerDone }()

	srv, err := agenttransport.New(write("server.crt", sc), write("server.key", sk), caFile, pool, mbus, log)
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

	// Run a real ICMP probe to loopback through the full pipeline when sockets are
	// permitted; otherwise the e2e still validates the noop path.
	icmpOK := loopbackICMPWorks(ctx)
	caps := []string{"noop"}
	canaries := []agent.CanaryConfig{{Type: "noop", Interval: agent.Duration(50 * time.Millisecond)}}
	if icmpOK {
		caps = append(caps, "icmp")
		canaries = append(canaries, agent.CanaryConfig{
			Type: "icmp", Target: "127.0.0.1", Interval: agent.Duration(100 * time.Millisecond),
			Timeout: agent.Duration(time.Second), Params: map[string]string{"count": "2"},
		})
	}
	cfg := &agent.Config{
		ControlPlane: agent.ControlPlaneConfig{GRPCAddr: ln.Addr().String()},
		TLS: agent.TLSConfig{
			CertFile: write("client.crt", cc), KeyFile: write("client.key", ck),
			CAFile: caFile, ServerName: "localhost",
		},
		Agent:    agent.Meta{Hostname: "e2e-host", Capabilities: caps, HeartbeatInterval: agent.Duration(time.Second)},
		Buffer:   agent.BufferConfig{Dir: filepath.Join(dir, "buffer"), MaxRecords: 1000},
		Canaries: canaries,
	}
	reg := canary.NewRegistry()
	reg.Register("noop", canary.NewNoop)
	reg.Register("icmp", canary.NewICMP)
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
		if online && srv.AcceptedResults() > 0 && len(mtsdb.Query("netctl_probe_success", map[string]string{"tenant_id": tn.ID})) > 0 {
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
	// The forwarded noop result must be queryable in the TSDB, tenant-scoped, with
	// the control plane having stamped the tenant from the agent's certificate.
	noop := mtsdb.Query("netctl_probe_success", map[string]string{"tenant_id": tn.ID, "canary_type": "noop"})
	if len(noop) == 0 {
		t.Fatal("no noop probe-success series reached the TSDB for the agent's tenant")
	}
	if noop[0].Labels["agent_id"] != agentID {
		t.Errorf("unexpected series labels: %+v", noop[0].Labels)
	}

	// The ICMP probe's loss/latency series must reach the TSDB (S7 Done-when).
	if icmpOK {
		waitForSeries(t, mtsdb, "netctl_probe_loss_ratio", tn.ID, "icmp", 10*time.Second)
		loss := mtsdb.Query("netctl_probe_loss_ratio", map[string]string{"tenant_id": tn.ID, "canary_type": "icmp"})
		if len(loss) == 0 || loss[0].Value != 0 {
			t.Errorf("icmp loopback loss series = %+v, want one with value 0", loss)
		}
		if len(mtsdb.Query("netctl_probe_rtt_avg_ms", map[string]string{"tenant_id": tn.ID, "canary_type": "icmp"})) == 0 {
			t.Error("no icmp rtt.avg series reached the TSDB")
		}
		if loss[0].Labels["server_address"] != "127.0.0.1" {
			t.Errorf("icmp series server_address = %q, want 127.0.0.1", loss[0].Labels["server_address"])
		}
	} else {
		t.Log("ICMP sockets unavailable; skipped the ICMP-to-TSDB assertions")
	}
}

// loopbackICMPWorks reports whether an unprivileged/raw ICMP probe to loopback
// succeeds in this environment.
func loopbackICMPWorks(ctx context.Context) bool {
	c, err := canary.NewICMP(canary.Config{
		Type: "icmp", Target: "127.0.0.1", Timeout: time.Second,
		Params: map[string]string{"count": "1"},
	})
	if err != nil {
		return false
	}
	r, err := c.Run(ctx)
	return err == nil && r.Success
}

// waitForSeries polls until a matching series appears or the timeout elapses.
func waitForSeries(t *testing.T, w *tsdb.Memory, metric, tenantID, canaryType string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if len(w.Query(metric, map[string]string{"tenant_id": tenantID, "canary_type": canaryType})) > 0 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
