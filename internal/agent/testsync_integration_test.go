// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

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

	"github.com/ctlplne/probectl/internal/agent"
	"github.com/ctlplne/probectl/internal/agenttransport"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/canary"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsync"
)

// TestCentralTestsReachOnlyTheirTenantsAgents is the G9 runtime proof: two
// tenants, one REAL agent runtime each with NO local canaries, a real
// control-plane transport and Postgres. A test defined centrally for tenant A
// runs on A's agent and yields results only in A; B's test only in B. A test
// created later reaches the running agent (heartbeat nudge + pull) without a
// restart, and a deleted test stops.
func TestCentralTestsReachOnlyTheirTenantsAgents(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	log := logging.New(io.Discard, "error", "json")
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ca, err := crypto.GenerateCA("probectl-g9-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := write("ca.crt", ca.CertPEM())
	sc, sk, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	src, err := testsync.NewSource(pool, priv)
	if err != nil {
		t.Fatal(err)
	}

	mbus := bus.NewMemory()
	mtsdb := tsdb.NewMemory()
	consumerCtx, stopConsumer := context.WithCancel(ctx)
	consumerDone := make(chan struct{})
	go func() {
		_ = pipeline.NewConsumer(mbus, mtsdb, "g9", log).WithTenantBinding(pipeline.NewRegistryBinding(pool)).Run(consumerCtx)
		close(consumerDone)
	}()
	defer func() { stopConsumer(); <-consumerDone }()

	srv, err := agenttransport.New(write("server.crt", sc), write("server.key", sk), caFile, pool, mbus, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	srv.WithTestBundles(src)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, stopSrv := context.WithCancel(ctx)
	srvDone := make(chan struct{})
	go func() { _ = srv.ServeListener(srvCtx, ln); close(srvDone) }()
	defer func() { stopSrv(); <-srvDone }()

	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	ta, err := store.NewTenants(pool).Create(ctx, "g9-a-"+sfx, "G9 A")
	if err != nil {
		t.Fatal(err)
	}
	tb, err := store.NewTenants(pool).Create(ctx, "g9-b-"+sfx, "G9 B")
	if err != nil {
		t.Fatal(err)
	}
	createTest := func(tenant, name, target string) string {
		var id string
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, func(ctx context.Context, s tenancy.Scope) error {
			tt, err := (store.Tests{}).Create(ctx, s, store.TestInput{Name: name, Type: "noop", Target: target,
				IntervalSeconds: 1, TimeoutSeconds: 1, Enabled: true})
			if err != nil {
				return err
			}
			id = tt.ID
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return id
	}
	idA := createTest(ta.ID, "a-1", "a-target")
	idB := createTest(tb.ID, "b-1", "b-target")

	startAgent := func(name, tenant string) {
		agentID := newUUID(t)
		cc, ck, err := ca.IssueClientCert(agentID, crypto.AgentSPIFFEID(tenant, agentID), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		certFile := write(name+"/identity/cert.pem", cc)
		write(name+"/identity/"+agent.TestSyncPublicKeyFileName, pub) // as enrollment writes it
		cfg := &agent.Config{
			ControlPlane: agent.ControlPlaneConfig{GRPCAddr: ln.Addr().String()},
			TLS: agent.TLSConfig{CertFile: certFile, KeyFile: write(name+"/identity/key.pem", ck),
				CAFile: caFile, ServerName: "localhost"},
			Agent:    agent.Meta{Hostname: name, Capabilities: []string{"noop"}, HeartbeatInterval: agent.Duration(time.Second)},
			Buffer:   agent.BufferConfig{Dir: filepath.Join(dir, name, "buffer"), MaxRecords: 1000},
			TestSync: agent.TestSyncConfig{MinInterval: agent.Duration(time.Second), Interval: agent.Duration(time.Hour)},
			// No local canaries: everything this agent runs came from the bundle.
		}
		cfg.TestSync = withDefaults(t, cfg)
		reg := canary.NewRegistry()
		reg.Register("noop", canary.NewNoop)
		a, err := agent.New(cfg, reg, log)
		if err != nil {
			t.Fatalf("new agent %s: %v", name, err)
		}
		actx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { _ = a.Run(actx); close(done) }()
		t.Cleanup(func() { stop(); <-done })
	}
	startAgent("agent-a", ta.ID)
	startAgent("agent-b", tb.ID)

	series := func(tenant, testID string) int {
		return len(mtsdb.Query("probectl_probe_success", map[string]string{"tenant_id": tenant, "test_id": testID}))
	}
	eventually(t, 20*time.Second, "each agent runs its own tenant's central test", func() bool {
		return series(ta.ID, idA) > 0 && series(tb.ID, idB) > 0
	})
	if series(ta.ID, idB) != 0 || series(tb.ID, idA) != 0 {
		t.Fatal("ISOLATION BREACH: a tenant's central test produced results in the other tenant")
	}

	// A test created while the agents run reaches A's agent through the
	// heartbeat nudge (the poll interval is an hour, so only the nudge can
	// deliver it; the control plane sets a 30s heartbeat), and never B's.
	idA2 := createTest(ta.ID, "a-2", "a2-target")
	eventually(t, 50*time.Second, "a newly created test reaches the running agent", func() bool {
		return series(ta.ID, idA2) > 0
	})
	if series(tb.ID, idA2) != 0 {
		t.Fatal("ISOLATION BREACH: tenant A's new test ran for tenant B")
	}
	var applied *int64
	eventually(t, 50*time.Second, "the agent reports the applied version", func() bool {
		_ = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(ta.ID)), pool, func(ctx context.Context, s tenancy.Scope) error {
			return s.Q.QueryRow(ctx, `SELECT max(test_set_version) FROM agents`).Scan(&applied)
		})
		return applied != nil && *applied == 3
	})
}

func withDefaults(t *testing.T, cfg *agent.Config) agent.TestSyncConfig {
	t.Helper()
	ts := cfg.TestSync
	if ts.PublicKeyFile == "" {
		ts.PublicKeyFile = filepath.Join(filepath.Dir(cfg.TLS.CertFile), agent.TestSyncPublicKeyFileName)
	}
	if ts.MaxTests == 0 {
		ts.MaxTests = 200
	}
	if ts.StateDir == "" {
		ts.StateDir = filepath.Join(cfg.Buffer.Dir, "testsync")
	}
	return ts
}

func eventually(t *testing.T, within time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting until %s", within, what)
}
