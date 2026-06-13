// SPDX-License-Identifier: LicenseRef-probectl-TBD

package main

// CODE-005: run() had grown to ~940 lines doing everything inline. This file
// holds per-subsystem builder/registration helpers split out of it, so run()
// reads as a sequence of named steps and each subsystem's wiring is testable
// and findable on its own. (Decomposition is incremental — more blocks move
// here over time; the goal is that run() never again becomes the one place
// every wiring detail hides.)

import (
	"context"
	"fmt"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/secrets"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
)

// setupSecretsAndEnvelope resolves secret-reference config through the
// configured backends (S41 — fail closed on a partial credential set) and
// installs the deployment envelope as the at-rest sealer (SEC-002/S-T6/
// TENANT-106). It returns the resolver (for backend-health + the ee/ attach
// seam) and whether the envelope key was generated on first boot. Extracted
// from run() (CODE-005).
func setupSecretsAndEnvelope(cfg *config.Config) (*secrets.Resolver, bool, error) {
	resolver, err := secrets.FromEnv(0)
	if err != nil {
		return nil, false, fmt.Errorf("secret backends: %w", err)
	}
	if err := cfg.ResolveSecretRefs(context.Background(), resolver.Resolve); err != nil {
		return nil, false, err
	}
	envelopeGenerated := false
	if cfg.EnvelopeKey == "" && cfg.EnvelopeKeyFile != "" {
		// SEC-002: encryption-by-default — load the deployment KEK from the file,
		// generating + persisting one on first boot. An explicit env key wins.
		kek, generated, kerr := tenantcrypto.LoadOrGenerateKeyFile(cfg.EnvelopeKeyFile)
		if kerr != nil {
			return nil, false, fmt.Errorf("envelope key file: %w", kerr)
		}
		cfg.EnvelopeKey = kek
		if cfg.EnvelopeKeyID == "dev" {
			cfg.EnvelopeKeyID = "file"
		}
		envelopeGenerated = generated
	}
	if cfg.EnvelopeKey != "" {
		sealer, serr := tenantcrypto.NewEnvelopeSealer(cfg.EnvelopeKeyID, cfg.EnvelopeKey)
		if serr != nil {
			return nil, false, fmt.Errorf("envelope sealer: %w", serr)
		}
		tenantcrypto.SetPrimary(sealer)
	} else if cfg.RequireAtRestEncryption {
		// TENANT-106: fail closed — refuse to start rather than silently write
		// tenant secrets in plaintext when encryption is required.
		return nil, false, fmt.Errorf("PROBECTL_REQUIRE_AT_REST_ENCRYPTION is set but no envelope key is resolvable " +
			"(set PROBECTL_ENVELOPE_KEY, or the licensed per-tenant keyring) — refusing to start with plaintext at-rest storage")
	}
	return resolver, envelopeGenerated, nil
}

// buildIngestWriter selects the tsdb.Writer used by the INGEST consumers.
// SCALE-001: when remote-write batching is enabled (default ON in prometheus
// mode), it wraps the raw writer in a BatchingWriter so concurrent results
// coalesce into one POST instead of one POST per result. Only the ingest path
// is wrapped — read/query/gauge paths keep the concrete tsdbWriter so their
// type assertions (e.g. *tsdb.Prometheus in registerLossGauges) still hold.
// Returns the writer to feed consumers and an optional closer for the wrapper.
func buildIngestWriter(cfg *config.Config, tsdbWriter tsdb.Writer) (tsdb.Writer, func() error) {
	if !cfg.RemoteWriteBatchEnabled {
		return tsdbWriter, nil
	}
	bw := tsdb.NewBatchingWriter(tsdbWriter, cfg.RemoteWriteBatchSeries, cfg.RemoteWriteBatchWait)
	return bw, bw.Close
}

// registerLossGauges exposes the pipeline/bus/clock-skew loss counters that
// already exist as sampled gauges on /metrics (CORRECT-009) — probectl observes
// probectl (§8), so operators can alert on data loss instead of it being
// invisible until a customer notices missing data. Safe to call once at boot.
func registerLossGauges(m *metrics.Registry, resultBus bus.Bus, tsdbWriter tsdb.Writer) {
	m.Gauge("probectl_pipeline_future_clamped",
		"Samples clamped because their timestamp was implausibly far in the future (agent clock skew, CORRECT-012).",
		func() float64 { return float64(pipeline.FutureClamped()) })
	m.Gauge("probectl_pipeline_max_future_skew_ms",
		"Largest future clock skew observed across all samples, in milliseconds.",
		func() float64 { return float64(pipeline.MaxObservedFutureSkewMillis()) })
	// WIRE-001: cross-tenant injection attempts dropped fail-closed by tenant
	// verification across every bus-published plane — surfaced so the
	// tenant-isolation dashboard can alert on it instead of it hiding in logs.
	m.Gauge("probectl_pipeline_tenant_rejected_total",
		"Records dropped fail-closed by tenant verification (cross-tenant injection attempts / shared-lane refusals, WIRE-001).",
		func() float64 { return float64(pipeline.TenantRejectedTotal()) })
	if kb, ok := resultBus.(*bus.Kafka); ok {
		m.Gauge("probectl_bus_produced", "Broker-acked records published to the bus.",
			func() float64 { return float64(kb.Stats().Produced) })
		m.Gauge("probectl_bus_failed", "Records accepted into the producer buffer that failed asynchronously after retries.",
			func() float64 { return float64(kb.Stats().Failed) })
		m.Gauge("probectl_bus_shed", "Records shed at the full in-flight buffer (broker degraded backpressure drop).",
			func() float64 { return float64(kb.Stats().Shed) })
		m.Gauge("probectl_bus_handler_errors", "Consumed records whose handler errored, leaving the offset uncommitted for redelivery (SCALE-007/CODE-007).",
			func() float64 { return float64(kb.Stats().HandlerErrors) })
		m.Gauge("probectl_bus_buffered", "Records currently buffered in the async producer (in flight).",
			func() float64 { return float64(kb.Stats().Buffered) })
	}
	if p, ok := tsdbWriter.(*tsdb.Prometheus); ok {
		m.Gauge("probectl_tsdb_remote_write_rejected", "Samples permanently rejected by the remote-write upstream with a 4xx (out-of-order/too-old, CORRECT-003).",
			func() float64 { return float64(p.RejectedPermanent()) })
	}
}
