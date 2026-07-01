// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/proto"

	"github.com/imfeelingtheagi/probectl/internal/agenttransport"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	agentv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
)

func TestAgentResultPushLatency(t *testing.T) {
	hp, ok := HotPathByID("hp-agent-result-push")
	if !ok {
		t.Fatal("missing hp-agent-result-push catalog row")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	b := bus.NewMemory()
	store := tsdb.NewMemory()
	consumer := pipeline.NewConsumer(b, store, "perf-agent-result-push", log)

	pipeCtx, stopPipe := context.WithCancel(ctx)
	pipeDone := make(chan error, 1)
	go func() { pipeDone <- consumer.Run(pipeCtx) }()
	if !b.WaitForSubscribers(ctx, bus.NetworkResultsTopic, 1) {
		t.Fatal("result pipeline did not subscribe to the network results topic")
	}
	t.Cleanup(func() {
		stopPipe()
		if err := <-pipeDone; err != nil {
			t.Errorf("result pipeline stopped with error: %v", err)
		}
		if err := b.Close(); err != nil {
			t.Errorf("close bus: %v", err)
		}
	})

	dir := t.TempDir()
	ca, err := crypto.GenerateCA("probectl-perf-ca", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caFile := writePerfTemp(t, dir, "ca.crt", ca.CertPEM())
	serverCert, serverKey, err := ca.IssueServerCert("localhost", []string{"localhost", "127.0.0.1"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := agenttransport.New(
		writePerfTemp(t, dir, "server.crt", serverCert),
		writePerfTemp(t, dir, "server.key", serverKey),
		caFile,
		nil,
		b,
		nil,
		log,
	)
	if err != nil {
		t.Fatalf("new agent transport: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srvCtx, stopSrv := context.WithCancel(ctx)
	srvDone := make(chan error, 1)
	go func() { srvDone <- srv.ServeListener(srvCtx, ln) }()
	t.Cleanup(func() {
		stopSrv()
		if err := <-srvDone; err != nil {
			t.Errorf("agent transport stopped with error: %v", err)
		}
	})

	const (
		tenantID = "tenant-perf-result-push"
		agentID  = "agent-perf-result-push"
		samples  = 32
	)
	clientCert, clientKey, err := ca.IssueClientCert(agentID, crypto.AgentSPIFFEID(tenantID, agentID), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg, err := crypto.ClientMTLSConfig(
		writePerfTemp(t, dir, "client.crt", clientCert),
		writePerfTemp(t, dir, "client.key", clientKey),
		caFile,
	)
	if err != nil {
		t.Fatal(err)
	}
	clientCfg.ServerName = "localhost"
	conn, err := grpc.NewClient(ln.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientCfg)))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer conn.Close()
	client := agentv1.NewAgentServiceClient(conn)

	sendResultPush(ctx, t, client, "perf-warmup", 0)

	var lats Latencies
	totalStart := time.Now()
	for i := 1; i <= samples; i++ {
		start := time.Now()
		sendResultPush(ctx, t, client, "perf-result-push", i)
		lats.Record(time.Since(start))
	}
	elapsed := time.Since(totalStart)

	got := store.Query("probectl_probe_success", map[string]string{
		"tenant_id":   tenantID,
		"agent_id":    agentID,
		"canary_type": "perf-result-push",
	})
	if len(got) != samples {
		t.Fatalf("stored result-push samples = %d, want %d", len(got), samples)
	}
	for i, s := range got {
		if s.Value != 1 {
			t.Fatalf("stored result-push sample %d success = %v, want 1", i, s.Value)
		}
	}
	forged := store.Query("probectl_probe_success", map[string]string{"tenant_id": "payload-forged-tenant"})
	if len(forged) != 0 {
		t.Fatalf("stored forged payload tenant samples = %d, want 0", len(forged))
	}

	stat := lats.Summary()
	throughput := float64(samples) / elapsed.Seconds()
	t.Logf("AGENT_RESULT_PUSH_LATENCY_RESULT id=%s streams=%d ack_latency=%s throughput=%.1f results/s stored_series=%d",
		hp.ID, samples, stat, throughput, len(got))

	if stat.P50 > hp.Targets.P50 || stat.P95 > hp.Targets.P95 || stat.P99 > hp.Targets.P99 {
		t.Fatalf("%s exceeded targets: got p50=%s p95=%s p99=%s; want <= p50=%s p95=%s p99=%s",
			hp.ID, stat.P50, stat.P95, stat.P99, hp.Targets.P50, hp.Targets.P95, hp.Targets.P99)
	}
	if throughput < hp.Targets.MinThroughputPerSecond {
		t.Fatalf("%s throughput = %.1f results/s, want >= %.1f", hp.ID, throughput, hp.Targets.MinThroughputPerSecond)
	}
}

func sendResultPush(ctx context.Context, t *testing.T, client agentv1.AgentServiceClient, canaryType string, seq int) {
	t.Helper()

	rpcCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	freshCtx, err := agenttransport.FreshnessMetadata(rpcCtx)
	if err != nil {
		t.Fatalf("freshness metadata: %v", err)
	}
	stream, err := client.StreamResults(freshCtx)
	if err != nil {
		t.Fatalf("stream results: %v", err)
	}
	payload, err := proto.Marshal(&resultv1.Result{
		TenantId:          "payload-forged-tenant",
		AgentId:           "payload-forged-agent",
		CanaryType:        canaryType,
		ServerAddress:     fmt.Sprintf("198.51.100.%d", seq),
		StartTimeUnixNano: time.Now().Add(time.Duration(seq) * time.Millisecond).UnixNano(),
		DurationNano:      int64(10 * time.Millisecond),
		Success:           true,
	})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	if err := stream.Send(&agentv1.StreamResultsRequest{
		Type:              "icmp",
		Payload:           payload,
		ObservedUnixNanos: time.Now().UnixNano(),
	}); err != nil {
		t.Fatalf("send result: %v", err)
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("results ack: %v", err)
	}
	if ack.GetAccepted() != 1 {
		t.Fatalf("accepted = %d, want 1", ack.GetAccepted())
	}
}

func writePerfTemp(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}
