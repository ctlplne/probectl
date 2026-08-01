// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package perf

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/store/tsdb"
)

type deadlineFlusherBus struct {
	flushDeadline time.Time
}

func (*deadlineFlusherBus) Publish(context.Context, string, []byte, []byte) error { return nil }
func (*deadlineFlusherBus) Subscribe(context.Context, string, string, bus.Handler) error {
	return nil
}
func (*deadlineFlusherBus) Close() error { return nil }
func (b *deadlineFlusherBus) Flush(ctx context.Context) error {
	b.flushDeadline, _ = ctx.Deadline()
	return context.DeadlineExceeded
}

func TestWarmKafkaTopicBoundsDependencyFailure(t *testing.T) {
	b := &deadlineFlusherBus{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	start := time.Now()
	err := warmKafkaTopic(ctx, b)
	if err == nil || !strings.Contains(err.Error(), "warmup flush") {
		t.Fatalf("warmup error = %v, want contextual flush failure", err)
	}
	remaining := b.flushDeadline.Sub(start)
	if remaining <= 0 || remaining > fullStackKafkaFlushTimeout+time.Second {
		t.Fatalf("warmup flush deadline in %s, want a positive bound <= %s", remaining, fullStackKafkaFlushTimeout)
	}
}

type skippedFirstProbeBus struct {
	published int
}

func (b *skippedFirstProbeBus) Publish(context.Context, string, []byte, []byte) error {
	b.published++
	return nil
}
func (*skippedFirstProbeBus) Subscribe(context.Context, string, string, bus.Handler) error {
	return nil
}
func (*skippedFirstProbeBus) Close() error { return nil }

func TestWaitFullStackReadyRepublishesAfterColdAssignmentRace(t *testing.T) {
	b := &skippedFirstProbeBus{}
	count := func(context.Context, string) (float64, error) {
		// Model Kafka's FromEnd behavior when the first record lands before
		// consumer-group assignment: only a later probe reaches the writer.
		if b.published >= 2 {
			return 1, nil
		}
		return 0, nil
	}
	consumerErr := make(chan error)
	if err := waitFullStackReady(context.Background(), b, count, "lscold", consumerErr); err != nil {
		t.Fatal(err)
	}
	if b.published < 2 {
		t.Fatalf("readiness publishes = %d, want a retry after the skipped first record", b.published)
	}
}

// memCounter emulates the two instant queries the driver issues against a
// memory store with PROMETHEUS semantics: count() counts DISTINCT series,
// while Memory.Query returns one entry per sample — so dedup by label set.
func memCounter(w *tsdb.Memory, cfg IngestConfig) QueryCounter {
	distinct := func(tenant string) int {
		seen := map[string]bool{}
		for _, s := range w.Query(successMetric, map[string]string{"tenant_id": tenant}) {
			keys := make([]string, 0, len(s.Labels))
			for k, v := range s.Labels {
				keys = append(keys, k+"="+v)
			}
			sort.Strings(keys)
			seen[strings.Join(keys, "|")] = true
		}
		return len(seen)
	}
	return func(_ context.Context, promql string) (float64, error) {
		switch {
		case strings.Contains(promql, `tenant_id=~`):
			// The settle selector: this run's distinct series across all 3
			// metrics — derived from the success metric per tenant.
			total := 0
			for t := 0; t < cfg.Tenants; t++ {
				total += distinct(fmt.Sprintf("%s-tenant-%04d", cfg.Namespace, t))
			}
			return float64(total * seriesPerResult), nil
		case strings.Contains(promql, `tenant_id="`):
			from := strings.Index(promql, `tenant_id="`) + len(`tenant_id="`)
			to := strings.Index(promql[from:], `"`)
			return float64(distinct(promql[from : from+to])), nil
		}
		return 0, fmt.Errorf("unexpected query %q", promql)
	}
}

// The full driver on the in-memory stack: settle-on-query, per-tenant
// correctness, latency capture, and the report shape the operator commits.
func TestDriveFullStackOnMemoryStack(t *testing.T) {
	profile, err := ProfileFor(TierM, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	b := bus.NewMemory()
	defer b.Close()
	w := tsdb.NewMemory()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	rep, err := DriveFullStack(ctx, b, w, memCounter(w, withNS(profile.Ingest, "lsunit")), profile, true, "lsunit")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s", rep)
	if len(rep.Scale.Violations) != 0 {
		t.Fatalf("violations on a healthy run: %v", rep.Scale.Violations)
	}
	if rep.Scale.Ingest.Published != profile.Ingest.TotalResults() {
		t.Fatalf("published %d, want %d", rep.Scale.Ingest.Published, profile.Ingest.TotalResults())
	}
	if rep.UniqueSeries != profile.Ingest.Tenants*profile.Ingest.AgentsPerTenant*profile.Ingest.TestsPerAgent*seriesPerResult {
		t.Fatalf("unique series math wrong: %d", rep.UniqueSeries)
	}
	if rep.TenantsQueried != profile.Ingest.Tenants {
		t.Fatalf("queried %d tenants, want %d", rep.TenantsQueried, profile.Ingest.Tenants)
	}
	if !strings.Contains(rep.String(), "PASS") {
		t.Fatalf("report = %s", rep)
	}
}

func TestFullStackKafkaBufferScalesWithReferenceBurst(t *testing.T) {
	profile, err := ProfileFor(TierL, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := fullStackKafkaMaxBuffered(profile, 1); got < profile.Ingest.TotalResults() {
		t.Fatalf("full-scale Kafka buffer = %d, want at least %d", got, profile.Ingest.TotalResults())
	}
	if got := fullStackKafkaMaxBuffered(profile, 0.05); got != bus.DefaultMaxBuffered {
		t.Fatalf("CI Kafka buffer drifted: %d", got)
	}
	if got := fullStackSubscribeWorkers(profile, 1); got < 64 {
		t.Fatalf("full-scale subscribe workers = %d, want reference-scale fan-out", got)
	}
	if got := fullStackSubscribeWorkers(profile, 0.05); got != 1 {
		t.Fatalf("CI subscribe workers drifted: %d", got)
	}
	if got := fullStackWriteWorkers(profile, false); got != fullStackSubscribeWorkers(profile, 1) {
		t.Fatalf("full-scale write workers = %d, want subscribe worker parity", got)
	}
	if got := fullStackBatchSeries(profile, 1); got < 5000 {
		t.Fatalf("full-scale batch series = %d, want reference-scale batches", got)
	}
	if got := fullStackBatchWait(1); got >= 50*time.Millisecond {
		t.Fatalf("full-scale batch wait = %s, want lower than CI/default", got)
	}
}

func TestFullStackConfirmationRangeCoversGeneratedTimestamps(t *testing.T) {
	profile, err := ProfileFor(TierL, 1)
	if err != nil {
		t.Fatal(err)
	}
	span := ingestTimestampSpan(profile.Ingest)
	if got := fullStackConfirmationRange(profile.Ingest); got <= span {
		t.Fatalf("confirmation range %s must exceed generated timestamp span %s", got, span)
	}
	xxl, err := ProfileFor(TierXXL, 1)
	if err != nil {
		t.Fatal(err)
	}
	if got := ingestTimestampSpan(xxl.Ingest); got > time.Minute {
		t.Fatalf("XXL generated timestamp span = %s, want compressed recent samples", got)
	}
	if got := promDuration(1500 * time.Millisecond); got != "2s" {
		t.Fatalf("prom duration rounding = %q", got)
	}
	expr := fullStackTotalSeriesExpr("lsx", "10m")
	for _, metric := range []string{"probectl_probe_success", "probectl_probe_duration_seconds", "probectl_probe_rtt_avg_ms"} {
		if !strings.Contains(expr, metric) {
			t.Fatalf("confirmation expr missing %s: %s", metric, expr)
		}
	}
}

// A store that never confirms (count stays 0) must surface INGEST INCOMPLETE
// — the gate fails loudly instead of reporting throughput over lost data.
func TestDriveFullStackIncompleteIngestFails(t *testing.T) {
	profile, err := ProfileFor(TierS, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	profile.Ingest.SettleTimeout = 300 * time.Millisecond
	b := bus.NewMemory()
	defer b.Close()
	w := tsdb.NewMemory()
	blind := func(_ context.Context, promql string) (float64, error) {
		if strings.Contains(promql, `tenant_id="lsgone-ready"`) {
			return 1, nil
		}
		return 0, nil
	}

	rep, err := DriveFullStack(context.Background(), b, w, blind, profile, true, "lsgone")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, v := range rep.Scale.Violations {
		found = found || strings.Contains(v, "INGEST INCOMPLETE")
	}
	if !found {
		t.Fatalf("missing completeness violation: %v", rep.Scale.Violations)
	}
	if !strings.Contains(rep.String(), "FAIL") {
		t.Fatalf("report must say FAIL: %s", rep)
	}
}

// A tenant seeing the wrong series count is a scoping violation — the query
// leg is a correctness check, not just a stopwatch.
func TestDriveFullStackQueryLegCatchesScopingErrors(t *testing.T) {
	profile, err := ProfileFor(TierS, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	b := bus.NewMemory()
	defer b.Close()
	w := tsdb.NewMemory()
	good := memCounter(w, withNS(profile.Ingest, "lsbad"))
	lying := func(ctx context.Context, promql string) (float64, error) {
		v, err := good(ctx, promql)
		if strings.Contains(promql, `tenant_id="`) {
			return v + 1, err // one foreign series leaked into the tenant view
		}
		return v, err
	}

	rep, err := DriveFullStack(context.Background(), b, w, lying, profile, true, "lsbad")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, v := range rep.Scale.Violations {
		found = found || strings.Contains(v, "scoping/completeness")
	}
	if !found {
		t.Fatalf("missing scoping violation: %v", rep.Scale.Violations)
	}
}

// SCALE-002: L/XL/XXL profiles have more than eight tenants. The full-stack gate
// must check every tenant, because a missing tenant past the old sample window
// can still satisfy the namespace total count.
func TestDriveFullStackQueryLegChecksEveryTenant(t *testing.T) {
	profile, err := ProfileFor(TierL, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Ingest.Tenants <= 8 {
		t.Fatalf("test needs a many-tenant profile, got %d tenants", profile.Ingest.Tenants)
	}
	profile.Ingest.SettleTimeout = 300 * time.Millisecond

	b := bus.NewMemory()
	defer b.Close()
	w := tsdb.NewMemory()
	const ns = "lsalltenants"
	good := memCounter(w, withNS(profile.Ingest, ns))
	missingTenant := profile.Ingest.Tenants - 1
	missingNeedle := fmt.Sprintf(`tenant_id="%s-tenant-%04d"`, ns, missingTenant)
	missing := func(ctx context.Context, promql string) (float64, error) {
		v, err := good(ctx, promql)
		if strings.Contains(promql, missingNeedle) {
			return 0, err
		}
		return v, err
	}

	rep, err := DriveFullStack(context.Background(), b, w, missing, profile, true, ns)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TenantsQueried != profile.Ingest.Tenants {
		t.Fatalf("queried %d tenants, want every tenant (%d)", rep.TenantsQueried, profile.Ingest.Tenants)
	}
	want := fmt.Sprintf("tenant %04d sees 0 success series", missingTenant)
	var found bool
	for _, v := range rep.Scale.Violations {
		found = found || strings.Contains(v, want)
	}
	if !found {
		t.Fatalf("missing violation for non-sampled tenant %04d: %v", missingTenant, rep.Scale.Violations)
	}
}

// The namespace isolates runs: identities carry the prefix, and an empty
// namespace keeps the historical shape (the in-process gate's contract).
func TestIngestNamespacePrefix(t *testing.T) {
	cfg := IngestConfig{Tenants: 2, AgentsPerTenant: 1, TestsPerAgent: 1, ResultsPerTest: 1, Namespace: "ls42"}
	ids := buildIdentities(cfg)
	if len(ids) != 2 || ids[0].tenant != "ls42-tenant-0000" || ids[1].tenant != "ls42-tenant-0001" {
		t.Fatalf("namespaced identities = %+v", ids)
	}
	cfg.Namespace = ""
	if ids := buildIdentities(cfg); ids[0].tenant != "tenant-0000" {
		t.Fatalf("empty namespace must keep the historical shape: %+v", ids)
	}
}

func withNS(c IngestConfig, ns string) IngestConfig {
	c.Namespace = ns
	return c
}
