// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package control

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/imfeelingtheagi/probectl/internal/bgp"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

// TestAnalyzerRunnerToBGPEventsAPI is W1's actual last-mile proof:
// recorded RIS wire fixture -> Python analyzer -> Go tenant-bound bridge ->
// Kafka -> production BGPIncidentConsumer -> Postgres/RLS -> /v1/bgp/events.
func TestAnalyzerRunnerToBGPEventsAPI(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		testsupport.SkipOrFatal(t, "python3 unavailable: %v", err)
	}
	brokers := testsupport.KafkaBrokers()
	if len(brokers) == 0 {
		testsupport.SkipOrFatal(t, "PROBECTL_TEST_KAFKA not set — analyzer e2e needs a real bus")
	}

	h, db := setupAPI(t)
	tenantA := freshTenant(t, db, "analyzer-e2e")
	tenantB := freshTenant(t, db, "analyzer-decoy")
	b, err := bus.NewKafka(brokers, 0, kgo.AllowAutoTopicCreation())
	if err != nil {
		t.Fatalf("kafka: %v", err)
	}
	defer b.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	consumer := NewBGPIncidentConsumer(b, BuildCorrelator(db.Pool(), 5*time.Minute, slog.Default()), slog.Default())
	consumerErr := make(chan error, 1)
	go func() { consumerErr <- consumer.Run(ctx) }()
	time.Sleep(2 * time.Second)

	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(t.TempDir(), "analyzer.json")
	configBody, err := json.Marshal(map[string]any{
		"tenant_id": tenantA,
		"collector": "rrc00",
		"monitored_prefixes": []map[string]any{{
			"prefix": "192.0.2.0/24", "expected_origins": []int{64496},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configFile, configBody, 0o600); err != nil {
		t.Fatal(err)
	}

	process := bgp.AnalyzerProcess{
		TenantID:   tenantA,
		Executable: python,
		Args: []string{
			"-m", "probectl_analyzer", "--config", configFile, "--replay",
			filepath.Join(repoRoot, "internal", "control", "testdata", "bgp", "ris-hijack.jsonl"),
		},
		Env: append(os.Environ(),
			"PYTHONPATH="+filepath.Join(repoRoot, "analyzer"),
			"PYTHONUNBUFFERED=1",
		),
	}
	runner, err := bgp.NewAnalyzerRunner(b, process, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.Run(ctx); err != nil {
		t.Fatalf("run analyzer: %v", err)
	}
	if err := b.Flush(context.Background()); err != nil {
		t.Fatalf("flush analyzer event: %v", err)
	}

	deadline := time.Now().Add(30 * time.Second)
	for {
		select {
		case err := <-consumerErr:
			t.Fatalf("BGP incident consumer stopped before API delivery: %v", err)
		default:
		}
		rec := apiReq(t, h, "GET", "/v1/bgp/events?prefix=192.0.2.0/24&limit=10", tenantA, nil)
		var response struct {
			Items []bgpEventItem `json:"items"`
		}
		mustJSON(t, rec, &response)
		if len(response.Items) > 0 {
			if response.Items[0].Prefix != "192.0.2.0/24" {
				t.Fatalf("BGP API item = %+v", response.Items[0])
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for analyzer event at /v1/bgp/events")
		}
		time.Sleep(250 * time.Millisecond)
	}

	decoy := apiReq(t, h, "GET", "/v1/bgp/events?prefix=192.0.2.0/24&limit=10", tenantB, nil)
	var decoyResponse struct {
		Items []bgpEventItem `json:"items"`
	}
	mustJSON(t, decoy, &decoyResponse)
	if len(decoyResponse.Items) != 0 {
		t.Fatalf("cross-tenant leak: decoy tenant received analyzer events: %s", decoy.Body)
	}
	t.Logf("analyzer event traversed Python -> Kafka -> incident store -> API for tenant %s", tenantA)
}
