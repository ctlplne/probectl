// SPDX-License-Identifier: LicenseRef-probectl-TBD

package perf

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/control"
	resultv1 "github.com/imfeelingtheagi/probectl/internal/gen/probectl/result/v1"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
)

type timedIncidentStore struct {
	inner           *incident.MemoryStore
	correlationRead Latencies
	incidentWrite   Latencies
}

func (s *timedIncidentStore) OpenIncidents(ctx context.Context, tenant string) ([]*incident.Incident, error) {
	start := time.Now()
	out, err := s.inner.OpenIncidents(ctx, tenant)
	s.correlationRead.Record(time.Since(start))
	return out, err
}

func (s *timedIncidentStore) Create(ctx context.Context, inc *incident.Incident) (*incident.Incident, error) {
	start := time.Now()
	out, err := s.inner.Create(ctx, inc)
	s.incidentWrite.Record(time.Since(start))
	return out, err
}

func (s *timedIncidentStore) AppendSignal(ctx context.Context, tenant, incidentID string, sig incident.Signal) (*incident.Incident, error) {
	start := time.Now()
	out, err := s.inner.AppendSignal(ctx, tenant, incidentID, sig)
	s.incidentWrite.Record(time.Since(start))
	return out, err
}

func TestProbeResultToIncidentLatency(t *testing.T) {
	hp, ok := HotPathByID("hp-probe-result-to-incident")
	if !ok {
		t.Fatal("missing hp-probe-result-to-incident catalog row")
	}

	iocs := opendata.NewIOCStore()
	iocs.Load([]opendata.IOC{{
		Type:       opendata.IOCTypeCIDR,
		Value:      "192.0.2.0/24",
		Source:     "perf_fixture",
		Category:   opendata.CategoryBotnetC2,
		Confidence: 90,
		License:    "test fixture",
	}})

	store := &timedIncidentStore{inner: incident.NewMemoryStore()}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	corr := incident.NewCorrelator(store, incident.DefaultWindow, log)
	consumer := control.NewIOCConsumer(nil, corr, iocs, log)

	const samples = 32
	var e2e Latencies
	ctx := context.Background()
	for i := 1; i <= samples; i++ {
		result := &resultv1.Result{
			TenantId:          "tenant-perf",
			CanaryType:        "icmp",
			ServerAddress:     fmt.Sprintf("192.0.2.%d", i),
			StartTimeUnixNano: time.Now().UnixNano(),
		}
		start := time.Now()
		if err := consumer.SinkResult(ctx, result); err != nil {
			t.Fatalf("sink result %d: %v", i, err)
		}
		e2e.Record(time.Since(start))
	}

	if got := store.inner.Len(); got != samples {
		t.Fatalf("probe-result incident count = %d, want %d", got, samples)
	}
	e2eStat := e2e.Summary()
	correlationStat := store.correlationRead.Summary()
	writeStat := store.incidentWrite.Summary()
	if correlationStat.Count != samples {
		t.Fatalf("correlation-read samples = %d, want %d", correlationStat.Count, samples)
	}
	if writeStat.Count != samples*2 {
		t.Fatalf("incident-write samples = %d, want %d (create + first signal append per incident)", writeStat.Count, samples*2)
	}
	t.Logf("PROBE_INCIDENT_LATENCY_RESULT id=%s ingest_e2e=%s correlation_read=%s incident_write=%s incidents=%d",
		hp.ID, e2eStat, correlationStat, writeStat, store.inner.Len())

	if e2eStat.P50 > hp.Targets.P50 || e2eStat.P95 > hp.Targets.P95 || e2eStat.P99 > hp.Targets.P99 {
		t.Fatalf("%s exceeded targets: got p50=%s p95=%s p99=%s; want <= p50=%s p95=%s p99=%s",
			hp.ID, e2eStat.P50, e2eStat.P95, e2eStat.P99, hp.Targets.P50, hp.Targets.P95, hp.Targets.P99)
	}
}
