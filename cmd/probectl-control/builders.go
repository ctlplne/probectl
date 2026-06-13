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
	"log/slog"
	"os"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/metrics"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/secrets"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
	"github.com/imfeelingtheagi/probectl/internal/version"
)

// serveStores holds the message bus + the per-plane stores the serve path wires
// up, plus a single aggregate closer so run() retires its long defer chain.
// pathCH is the concrete *pathstore.ClickHouse kept BEFORE the batching wrapper
// (TENANT-001: the ee silo router installs on it; the wrapper shares the pointer).
type serveStores struct {
	resultBus    bus.Bus
	tsdbWriter   tsdb.Writer
	ingestWriter tsdb.Writer
	pathStore    pathstore.Store
	pathCH       *pathstore.ClickHouse
	otelStore    otelstore.Store
	flowStore    flowstore.Store
	ebpfStore    ebpfstore.Store
}

// buildServeStores constructs the bus + every datastore the serve path needs,
// applies per-plane DB-level tenant reader scoping, and returns the bundle plus
// a single closer that tears every store down in reverse construction order.
// On ANY construction error it closes whatever it already opened (no leak on an
// early return — the CODE-001 closer-on-error guarantee) and returns the error.
// Extracted verbatim from run()'s store-construction phase (CODE-001).
func buildServeStores(cfg *config.Config, log *slog.Logger) (*serveStores, func(), error) {
	s := &serveStores{}
	// Reverse-order teardown, accumulated as each store opens.
	var closers []func()
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
	}
	fail := func(err error) (*serveStores, func(), error) {
		closeAll()
		return nil, nil, err
	}

	// Result pipeline: a message bus that the control plane consumes and writes
	// to the TSDB. The bus is shared with the agent transport (the publisher).
	memOpts := []bus.MemoryOption{bus.WithBuffer(cfg.BusMemoryBuffer)}
	if cfg.BusMemoryOverflow == "drop" {
		memOpts = append(memOpts, bus.WithOverflowDrop())
	}
	resultBus, err := bus.New(cfg.BusMode, cfg.BusBrokers, cfg.BusSecurity(), memOpts...)
	if k, ok := resultBus.(*bus.Kafka); ok {
		// SCALE-001: key-sharded parallel consume per subscription.
		k.WithSubscribeWorkers(cfg.BusWorkers)
	}
	if err != nil {
		return fail(fmt.Errorf("result bus: %w", err))
	}
	s.resultBus = resultBus
	closers = append(closers, func() { _ = resultBus.Close() })

	tsdbWriter, err := tsdb.NewWithLimits(cfg.TSDBMode, cfg.TSDBURL, cfg.TSDBMemoryRetention, int64(cfg.TSDBMemoryMaxBytes)) // U-018 bounds
	if err != nil {
		return fail(fmt.Errorf("tsdb: %w", err))
	}
	s.tsdbWriter = tsdbWriter
	closers = append(closers, func() { _ = tsdbWriter.Close() })

	// SCALE-001: the INGEST write path coalesces concurrent remote-writes into
	// one POST (per window/size), preserving per-message DLQ attribution.
	// Batching is ON by default in prometheus mode (see config). Only the write
	// path is wrapped — read/query paths keep the concrete writer so their type
	// assertions (alerting, snapshot, breaker gauges) hold.
	ingestWriter, ingestWriterClose := buildIngestWriter(cfg, tsdbWriter)
	if ingestWriterClose != nil {
		closers = append(closers, func() { _ = ingestWriterClose() })
		log.Info("remote-write batching enabled (ingest path)", "max_series", cfg.RemoteWriteBatchSeries, "max_wait", cfg.RemoteWriteBatchWait.String())
	}
	s.ingestWriter = ingestWriter

	pathStore, err := pathstore.NewRetained(cfg.PathStoreMode, cfg.PathStoreURL, cfg.PathRetentionDays)
	if err != nil {
		return fail(fmt.Errorf("path store: %w", err))
	}
	// TENANT-001: keep the concrete *pathstore.ClickHouse (before the batching
	// wrapper) so the ee silo router can be installed on it — the wrapper shares
	// the same pointer, so routing applies to all path writes/reads.
	s.pathCH, _ = pathStore.(*pathstore.ClickHouse)
	pathCH := s.pathCH
	// TENANT-004: DB-level reader scoping on the path plane (applied before the
	// batching wrapper). Defaults ON under multi-tenant/regulated.
	if err := installCHReaderPolicy(cfg.PathCHTenantScoping, cfg.PathCHReaderUser, "pathstore", "TENANT-004", log,
		func() (func(context.Context, string) error, bool) {
			if pathCH == nil {
				return nil, false
			}
			pathCH.WithTenantScoping(true)
			return pathCH.EnsureReaderRowPolicy, true
		}); err != nil {
		_ = pathStore.Close()
		return fail(err)
	}
	if cfg.PathStoreMode == "clickhouse" {
		// SCALE-009: cross-path batching window — N discoveries inside the
		// window cost one insert per table instead of a pair each.
		pathStore = pathstore.NewBatchingSaver(pathStore, log, 0, 0)
	}
	s.pathStore = pathStore
	closers = append(closers, func() { _ = pathStore.Close() })

	// OTLP traces + logs store (ARCH-001): memory in lightweight mode,
	// ClickHouse in production (tenant_id-led partition + retention TTL).
	otelStore, err := otelstore.New(cfg.OTelStoreMode, cfg.OTelStoreURL, cfg.OTelRetentionDays)
	if err != nil {
		return fail(fmt.Errorf("otelstore: %w", err))
	}
	s.otelStore = otelStore
	closers = append(closers, func() { _ = otelStore.Close() })
	// TENANT-003/004: DB-level reader scoping on the PII-heaviest plane. Under
	// the multi-tenant/regulated profile this defaults ON (defense-in-depth
	// above app WHERE scoping). EnsureReaderRowPolicy installs the
	// setting-scoped policy on the reader user so the query path cannot cross
	// tenants even if the WHERE is bypassed.
	if err := installCHReaderPolicy(cfg.OTelCHTenantScoping, cfg.OTelCHReaderUser, "otelstore", "TENANT-003", log,
		func() (func(context.Context, string) error, bool) {
			ch, ok := otelStore.(*otelstore.ClickHouse)
			if !ok {
				return nil, false
			}
			ch.WithTenantScoping(true)
			return ch.EnsureReaderRowPolicy, true
		}); err != nil {
		return fail(err)
	}

	flowStore, err := flowstore.New(cfg.FlowStoreMode, cfg.FlowStoreURL, cfg.FlowRetentionDays)
	if err != nil {
		return fail(fmt.Errorf("flow store: %w", err))
	}
	s.flowStore = flowStore
	closers = append(closers, func() { _ = flowStore.Close() })
	// SCALE-016: flow is the platform's highest-volume table. Keep-forever is a
	// legitimate choice (compliance) but must be a LOUD, explicit one — never
	// the silent default that grows the store unbounded.
	if cfg.FlowRetentionDays == 0 {
		log.Warn("FLOW RETENTION DISABLED: PROBECTL_FLOW_RETENTION_DAYS=0 — flows are kept FOREVER and the flow table will grow without bound. Set a finite value (default 90) unless you have an explicit retention requirement.")
	}
	// TENANT-102: DB-level reader scoping. When enabled, reads attach the
	// per-request tenant custom setting and the reader row policy constrains
	// the query path even if app-layer WHERE scoping is bypassed.
	if err := installCHReaderPolicy(cfg.FlowCHTenantScoping, cfg.FlowCHReaderUser, "flowstore", "TENANT-102", log,
		func() (func(context.Context, string) error, bool) {
			ch, ok := flowStore.(*flowstore.ClickHouse)
			if !ok {
				return nil, false
			}
			ch.WithTenantScoping(true)
			return ch.EnsureReaderRowPolicy, true
		}); err != nil {
		return fail(err)
	}

	// ARCH-008: durable eBPF flow/L7 aggregate store — the differentiator plane
	// gets history + restart survival instead of an in-RAM-only service map.
	ebpfStore, err := ebpfstore.New(cfg.EBPFStoreMode, cfg.EBPFStoreURL, cfg.EBPFRetentionDays)
	if err != nil {
		return fail(fmt.Errorf("ebpf store: %w", err))
	}
	s.ebpfStore = ebpfStore
	closers = append(closers, func() { _ = ebpfStore.Close() })
	// TENANT-004: DB-level reader scoping on the eBPF L7 edge plane. Defaults ON
	// under multi-tenant/regulated.
	if err := installCHReaderPolicy(cfg.EBPFCHTenantScoping, cfg.EBPFCHReaderUser, "ebpfstore", "TENANT-004", log,
		func() (func(context.Context, string) error, bool) {
			ch, ok := ebpfStore.(*ebpfstore.ClickHouse)
			if !ok {
				return nil, false
			}
			ch.WithTenantScoping(true)
			return ch.EnsureReaderRowPolicy, true
		}); err != nil {
		return fail(err)
	}

	return s, closeAll, nil
}

// installCHReaderPolicy applies DB-level tenant reader scoping to a
// ClickHouse-backed store when the plane's scoping flag is on: it turns on
// per-request tenant settings and, if a reader user is configured, installs the
// setting-scoped row policy (defense-in-depth above app WHERE scoping). When the
// store isn't ClickHouse-backed (memory mode) it is a no-op. Extracted from the
// four identical blocks in run() (CODE-001) — behavior is unchanged.
//
// store is taken as `any` because each plane's concrete type differs; the
// WithTenantScoping/EnsureReaderRowPolicy method set is asserted via the typed
// callback the caller supplies (so the concrete *ClickHouse keeps its fluent
// return). plane is the log label (e.g. "pathstore"); finding is the tag.
func installCHReaderPolicy(
	scopingOn bool,
	readerUser, plane, finding string,
	log *slog.Logger,
	enable func() (ensure func(context.Context, string) error, ok bool),
) error {
	if !scopingOn {
		return nil
	}
	ensure, ok := enable()
	if !ok {
		return nil // not ClickHouse-backed (e.g. memory mode) — nothing to scope
	}
	if readerUser == "" {
		log.Warn(plane+": tenant scoping on but reader user unset — reads carry the setting but no policy enforces it yet", "finding", finding)
		return nil
	}
	if err := ensure(context.Background(), readerUser); err != nil {
		return fmt.Errorf("%s reader policy: %w", plane, err)
	}
	log.Info(plane+": ClickHouse reader row policy installed", "finding", finding, "reader_user", readerUser)
	return nil
}

// dispatchEarlyCommand handles the subcommands that need NO database or config
// (version/gen-cert/support-bundle/preflight/backup-seal/backup-open) plus the
// unknown-command error. It returns handled=false for `serve` and the
// DB-backed subcommands so run() falls through to the configured path.
// Extracted verbatim from run()'s leading switch (CODE-001) — behavior is
// identical, including the exact usage string.
func dispatchEarlyCommand(cmd string) (handled bool, err error) {
	switch cmd {
	case "version", "-version", "--version":
		fmt.Println("probectl-control", version.Get())
		return true, nil
	case "gen-cert":
		// Self-signed TLS cert for the HTTPS-by-default quickstart; no DB needed.
		return true, genCert(os.Args[2:])
	case "support-bundle":
		// S-EE4: offline, secret-stripped diagnostics bundle.
		return true, supportBundle(os.Args[2:])
	case "preflight":
		// Sprint 8 (SEC-002/COMPLY-004): deployment self-check — envelope key
		// + operator storage-encryption duties (docs/hardening.md).
		return true, runPreflight(os.Args[2:])
	case "backup-seal":
		// OPS-002: stdin→stdout envelope-encryption filter for backup dumps.
		return true, backupSeal(os.Args[2:])
	case "backup-open":
		// OPS-002: decrypt an encrypted backup container for restore.
		return true, backupOpen(os.Args[2:])
	case "serve", "migrate", "mcp-stdio", "mcp-token", "scim-token", "agent-ca", "enroll-token", "revoke-agent", "revoke-enroll-token", "register-collector", "replay-deadletter":
		// fall through to the configured path in run()
		return false, nil
	default:
		return true, fmt.Errorf("unknown command %q (want: serve | migrate | mcp-stdio | mcp-token | scim-token | agent-ca | enroll-token | revoke-agent | revoke-enroll-token | register-collector | replay-deadletter | gen-cert | support-bundle | preflight | backup-seal | backup-open | version)", cmd)
	}
}

// dispatchDBCommand handles the one-shot subcommands that need the database but
// not the full serving stack (migrate, mcp-*, agent-ca, *-token, revoke-*,
// register-collector, replay-deadletter). It returns handled=false for `serve`
// (and anything else) so run() continues into the serving wiring. The DB is
// owned by run() (its `defer db.Close()` fires after this returns). Extracted
// verbatim from run()'s second switch (CODE-001).
func dispatchDBCommand(cmd string, cfg *config.Config, db *store.DB, log *slog.Logger) (handled bool, err error) {
	switch cmd {
	case "migrate":
		return true, runMigrations(context.Background(), db, log)
	case "mcp-stdio":
		return true, runMCPStdio(cfg, log, db)
	case "mcp-token":
		return true, runMCPToken(log, db, os.Args[2:])
	case "agent-ca":
		// Sprint 11: `agent-ca init` generates the enrollment hierarchy once.
		// `agent-ca export <file>` writes the public trust bundle (root +
		// intermediate) for PROBECTL_AGENT_TLS_CA_FILE.
		if len(os.Args) < 3 {
			return true, fmt.Errorf("usage: probectl-control agent-ca <init|export>")
		}
		switch os.Args[2] {
		case "init":
			return true, runAgentCAInit(context.Background(), db)
		case "export":
			return true, runAgentCAExport(context.Background(), db, os.Args[3:])
		default:
			return true, fmt.Errorf("usage: probectl-control agent-ca <init|export>")
		}
	case "enroll-token":
		return true, runEnrollToken(context.Background(), cfg, db, os.Args[2:])
	case "revoke-agent":
		// Sprint 12 (WIRE-003): persisted revocation; the RUNNING control
		// plane picks it up via its periodic deny-list refresh.
		return true, runRevokeAgent(context.Background(), db, os.Args[2:])
	case "revoke-enroll-token":
		// Voids an unredeemed join token early (redemption checks
		// revoked_at, so this takes effect immediately, no restart).
		return true, runRevokeEnrollToken(context.Background(), db, os.Args[2:])
	case "scim-token":
		return true, runSCIMToken(log, db, os.Args[2:])
	case "register-collector":
		// ARCH-011: register a bus-publishing collector (eBPF/flow/device) and
		// print its UUID identity; no cert (bus auth is separate).
		return true, runRegisterCollector(context.Background(), db, os.Args[2:])
	case "replay-deadletter":
		// ARCH-001: drain a probectl.deadletter.* topic and re-ingest each parked
		// record onto its source topic (operator-driven recovery after a store
		// outage outlived the retry budget).
		return true, runReplayDeadLetter(cfg, log, os.Args[2:])
	}
	return false, nil
}

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
	// SCALE-006: the lightweight in-memory bus defaults to drop-with-loss-
	// accounting so a stuck consumer cannot stall ingest. Surface the drop and
	// handler-loss counters so the loss is observable (never a silent drop).
	if mb, ok := resultBus.(*bus.Memory); ok {
		m.Gauge("probectl_bus_memory_dropped", "Messages dropped by the in-memory bus overflow policy when a subscriber buffer was full (SCALE-006). Nonzero = a lagging/stuck consumer.",
			func() float64 { return float64(mb.Dropped()) })
		m.Gauge("probectl_bus_memory_handler_lost", "Records dropped after the in-memory bus exhausted its redelivery budget (a permanently-failing handler, CORRECT-007).",
			func() float64 { return float64(mb.HandlerLost()) })
		m.Gauge("probectl_bus_memory_handler_errors", "Consumed records whose handler returned an error on the in-memory bus (CORRECT-007).",
			func() float64 { return float64(mb.HandlerErrors()) })
	}
	if p, ok := tsdbWriter.(*tsdb.Prometheus); ok {
		m.Gauge("probectl_tsdb_remote_write_rejected", "Samples permanently rejected by the remote-write upstream with a 4xx (out-of-order/too-old, CORRECT-003).",
			func() float64 { return float64(p.RejectedPermanent()) })
	}
}
