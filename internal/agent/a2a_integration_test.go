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

	"github.com/imfeelingtheagi/probectl/internal/a2a"
	"github.com/imfeelingtheagi/probectl/internal/agent"
	"github.com/imfeelingtheagi/probectl/internal/agenttransport"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/canary"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// TestAgentToAgentEndToEnd proves the S8 agent-to-agent Done-when: the control
// plane brokers two registered agents (one responds, one initiates), and the
// bidirectional measurement — forward and reverse one-way delay — reaches the
// TSDB, with a result from each agent.
func TestAgentToAgentEndToEnd(t *testing.T) {
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
	ca, err := crypto.GenerateCA("probectl-test-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := write("ca.crt", ca.CertPEM())
	sc, sk, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Control plane: broker + result pipeline into an in-memory TSDB.
	broker := a2a.NewBroker()
	mbus := bus.NewMemory()
	mtsdb := tsdb.NewMemory()
	consumerCtx, stopConsumer := context.WithCancel(ctx)
	consumerDone := make(chan struct{})
	go func() { _ = pipeline.NewConsumer(mbus, mtsdb, "a2a-e2e", log).Run(consumerCtx); close(consumerDone) }()
	defer func() { stopConsumer(); <-consumerDone }()

	srv, err := agenttransport.New(write("server.crt", sc), write("server.key", sk), caFile, pool, mbus, broker, log)
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

	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("a2a-e2e-%d", time.Now().UnixNano()), "A2A E2E")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	startAgent := func(name string) (string, func()) {
		agentID := newUUID(t)
		cc, ck, err := ca.IssueClientCert(agentID, crypto.AgentSPIFFEID(tn.ID, agentID), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		cfg := &agent.Config{
			ControlPlane: agent.ControlPlaneConfig{GRPCAddr: ln.Addr().String()},
			TLS: agent.TLSConfig{
				CertFile: write(name+".crt", cc), KeyFile: write(name+".key", ck),
				CAFile: caFile, ServerName: "localhost",
			},
			Agent:  agent.Meta{Hostname: name, Capabilities: []string{"a2a"}, HeartbeatInterval: agent.Duration(time.Second)},
			Buffer: agent.BufferConfig{Dir: filepath.Join(dir, name+"-buf"), MaxRecords: 1000},
			A2A: agent.A2AConfig{
				Enabled: true, AdvertiseHost: "127.0.0.1",
				PollInterval: agent.Duration(200 * time.Millisecond), ResponderTTL: agent.Duration(10 * time.Second),
			},
		}
		a, err := agent.New(cfg, canary.NewRegistry(), log)
		if err != nil {
			t.Fatalf("new agent %s: %v", name, err)
		}
		aCtx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() { _ = a.Run(aCtx); close(done) }()
		return agentID, func() { stop(); <-done }
	}

	respID, stopResp := startAgent("agent-resp")
	defer stopResp()
	initID, stopInit := startAgent("agent-init")
	defer stopInit()

	waitOnline := func(id string) bool {
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			var got *store.Agent
			err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tn.ID)), pool, func(ctx context.Context, s tenancy.Scope) error {
				a2, e := (store.Agents{}).Get(ctx, s, id)
				got = a2
				return e
			})
			if err == nil && got.Status == "online" {
				return true
			}
			time.Sleep(100 * time.Millisecond)
		}
		return false
	}
	if !waitOnline(respID) || !waitOnline(initID) {
		t.Fatal("agents did not register online")
	}

	// Broker the session: respID responds, initID initiates a 4-probe UDP test.
	if _, err := broker.StartSession(tn.ID, respID, initID, "udp", 4); err != nil {
		t.Fatalf("start session: %v", err)
	}

	waitSeries := func(metric, agentID string) bool {
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			for _, s := range mtsdb.Query(metric, map[string]string{"tenant_id": tn.ID, "canary_type": "a2a"}) {
				if s.Labels["agent_id"] == agentID {
					return true
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		return false
	}

	// Both directions, measured by the initiator, must reach the TSDB.
	if !waitSeries("probectl_probe_forward_avg_ms", initID) {
		t.Fatal("initiator forward one-way series did not reach the TSDB")
	}
	if !waitSeries("probectl_probe_reverse_avg_ms", initID) {
		t.Fatal("initiator reverse one-way series did not reach the TSDB")
	}
	// The responder (the other agent) must also report a result.
	if !waitSeries("probectl_probe_packets_received", respID) {
		t.Fatal("responder result did not reach the TSDB")
	}

	// Round-trip loss on loopback should be zero.
	loss := mtsdb.Query("probectl_probe_loss_ratio", map[string]string{"tenant_id": tn.ID, "canary_type": "a2a", "agent_id": initID})
	if len(loss) == 0 || loss[0].Value != 0 {
		t.Errorf("initiator round-trip loss = %+v, want one series with value 0", loss)
	}
}
