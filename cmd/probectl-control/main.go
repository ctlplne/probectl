// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Command probectl-control is the probectl control-plane API server.
//
// Subcommands:
//
//	probectl-control [serve]              run the stateless HTTP API server (default)
//	probectl-control migrate              apply database migrations and exit
//	probectl-control gen-cert             write a self-signed TLS cert (HTTPS quickstart)
//	probectl-control agent-ca             init/export the agent-enrollment CA
//	probectl-control enroll-token         mint a one-time agent join token
//	probectl-control revoke-enroll-token  void an unredeemed join token early
//	probectl-control register-collector   register a bus-publishing collector (eBPF/flow/device)
//	probectl-control revoke-agent         revoke an enrolled agent's identity
//	probectl-control mcp-stdio            serve MCP over stdio (local AI clients)
//	probectl-control mcp-token            mint an MCP access token
//	probectl-control scim-token           mint a SCIM provisioning token
//	probectl-control support-bundle       write a redacted diagnostics bundle
//	probectl-control backup-seal          encrypt a backup container
//	probectl-control backup-open          decrypt a backup container for restore
//	probectl-control preflight            validate config/connectivity and exit
//	probectl-control version              print build metadata and exit
//
// Configuration is read from PROBECTL_-prefixed environment variables
// (see docs/configuration.md).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/imfeelingtheagi/probectl/internal/a2a"
	"github.com/imfeelingtheagi/probectl/internal/agenttransport"
	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/cluster"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/control"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	"github.com/imfeelingtheagi/probectl/internal/enroll"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/lifecycle"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/otel/otlp"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/support"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
	"github.com/imfeelingtheagi/probectl/internal/threat"
	"github.com/imfeelingtheagi/probectl/internal/topology"
	"github.com/imfeelingtheagi/probectl/internal/version"
	"github.com/imfeelingtheagi/probectl/migrations"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if err := run(cmd); err != nil {
		// Last-resort CLI error reporting (the structured logger may not exist
		// yet, e.g. on a config-load failure).
		fmt.Fprintln(os.Stderr, "probectl-control:", err)
		os.Exit(1)
	}
}

func run(cmd string) error {
	// CODE-001: the no-DB subcommands (version/gen-cert/support-bundle/preflight/
	// backup-*) dispatch first; serve + the configured-path subcommands fall
	// through to the wiring below. Behavior is identical — this is mechanical
	// extraction of the leading dispatch switch off run()'s spine.
	if handled, err := dispatchEarlyCommand(cmd); handled {
		return err
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	// S41/SEC-002/S-T6: resolve secret-reference config and install the at-rest
	// envelope sealer (extracted to setupSecretsAndEnvelope — CODE-005).
	secretsResolver, envelopeGenerated, err := setupSecretsAndEnvelope(cfg)
	if err != nil {
		return err
	}
	// mcp-stdio uses stdout for its JSON-RPC channel, so its logs go to stderr.
	logOut := os.Stdout
	if cmd == "mcp-stdio" {
		logOut = os.Stderr
	}
	log := logging.New(logOut, cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)
	if envelopeGenerated {
		log.Warn("GENERATED a new at-rest envelope key — back this file up like any key material; losing it makes sealed values unreadable",
			"key_file", cfg.EnvelopeKeyFile, "key_id", cfg.EnvelopeKeyID)
	}

	// Dev auth (RED-001/SEC-001): never a default (U-001), and in a RELEASE
	// binary not even possible — the code path only exists behind the
	// devauth build tag. Even then, an explicit acknowledgment AND a
	// loopback-only bind are required. Fatal-exit, never just a warning.
	if cfg.AuthMode == "dev" {
		if !control.DevModeAvailable() {
			return fmt.Errorf("PROBECTL_AUTH_MODE=dev refused: dev auth is not compiled into this binary (release build). " +
				"For local evaluation build with -tags devauth (make build-devauth); production uses the default \"session\" mode (RED-001)")
		}
		if os.Getenv("PROBECTL_DEV_AUTH_ACK") != "i-understand" {
			return fmt.Errorf("PROBECTL_AUTH_MODE=dev refused: set PROBECTL_DEV_AUTH_ACK=i-understand to acknowledge that " +
				"EVERY request will receive an all-permissions principal with no authentication (local evaluation only)")
		}
		if !loopbackOnly(cfg.HTTPAddr) {
			return fmt.Errorf("PROBECTL_AUTH_MODE=dev refused: dev auth requires a loopback bind (got %q) — "+
				"set PROBECTL_HTTP_ADDR=127.0.0.1:<port>; never expose an unauthenticated all-permissions API on a network interface", cfg.HTTPAddr)
		}
	}

	// FIPS power-on self-test (S-EE1): exercise every crypto primitive (KATs)
	// before serving traffic and — in the FIPS artifact — assert the validated
	// module is active. Fail closed: a control plane whose crypto self-test
	// fails must not run (guardrail 3).
	if err := crypto.PowerOnSelfTest(); err != nil {
		return fmt.Errorf("crypto power-on self-test: %w", err)
	}
	if st := crypto.Status(); st.BuildTag || st.ModuleActive {
		log.Info("crypto self-test passed",
			"fips_build", st.BuildTag, "fips_module_active", st.ModuleActive,
			"fips_enforced", st.Enforced, "module_version", st.ModuleVersion)
	}

	db, err := store.Open(context.Background(), cfg.DatabaseURL,
		cfg.DatabaseMaxConns, cfg.DatabaseMinConns, cfg.DatabaseConnTimeout)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	// Multi-region (S-EE2): an optional local read replica for read locality.
	// Empty PROBECTL_DATABASE_READ_URL = reads stay on the writer.
	if err := db.WithReadReplica(context.Background(), cfg.DatabaseReadURL,
		cfg.DatabaseMaxConns, cfg.DatabaseMinConns, cfg.DatabaseConnTimeout); err != nil {
		return err
	}

	// CODE-001: the DB-backed one-shot subcommands (migrate, mcp-*, agent-ca,
	// *-token, revoke-*, register-collector, replay-deadletter) dispatch here,
	// after the DB is open (so `defer db.Close()` above still fires). `serve`
	// falls through to the long wiring path below. Pure mechanical extraction.
	if handled, err := dispatchDBCommand(cmd, cfg, db, log); handled {
		return err
	}

	if cfg.MigrateOnBoot {
		if err := runMigrations(context.Background(), db, log); err != nil {
			return err
		}
	}

	// TENANT-104: verify the RLS posture before serving — the app role must be
	// non-super, non-bypassrls, and every tenant table must FORCE row security.
	// Fail closed: a deployment where RLS is silently off must not run.
	if err := tenancy.AssertIsolationPosture(context.Background(), db.Pool()); err != nil {
		return fmt.Errorf("tenant isolation self-check failed: %w", err)
	}
	log.Info("tenant isolation posture verified (RLS forced, app role non-bypass)")

	log.Info("starting probectl-control", "version", version.Get().Version, "config", cfg)

	// Bus + per-plane stores (result bus, TSDB, ingest-batching writer, path,
	// otel, flow, ebpf) with their DB-level tenant reader scoping. Extracted to
	// buildServeStores (CODE-001): it returns the bundle plus ONE aggregate
	// closer that retires the long defer chain and closes everything on an early
	// error too.
	st, closeStores, err := buildServeStores(cfg, log)
	if err != nil {
		return err
	}
	defer closeStores()
	resultBus := st.resultBus
	tsdbWriter := st.tsdbWriter
	ingestWriter := st.ingestWriter
	pathStore := st.pathStore
	pathCH := st.pathCH
	otelStore := st.otelStore
	flowStore := st.flowStore
	ebpfStore := st.ebpfStore

	// ASN/geo enrichment for flows (S15 via S38): OPT-IN — Team Cymru is an
	// outbound DNS dependency, so it stays off unless explicitly enabled
	// (no-phone-home guardrail). Device-asserted AS numbers always flow through.
	// The same enricher instance powers the outage view's IP→scope join (S47a).
	var flowEnricher pipeline.FlowEnricher
	var ipEnricher *opendata.Enricher
	var asyncEnricher *pipeline.AsyncEnricher
	if cfg.FlowEnrichASN {
		en := opendata.NewEnricher(log)
		en.Register(opendata.NewCymru(net.DefaultResolver))
		// SCALE-011: enrichment is ASYNC on the flow hot path — cache hits
		// enrich inline, misses warm in the background and the record
		// proceeds unenriched (graceful degrade under lag).
		async := pipeline.NewAsyncEnricher(en, log)
		asyncEnricher = async
		flowEnricher = async
		ipEnricher = en
		log.Info("flow ASN enrichment enabled", "source", "team-cymru", "mode", "async")
	}

	// Brokers agent-to-agent measurement sessions; sessions are started by the
	// test API in a later sprint.
	a2aBroker := a2a.NewBroker()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the HTTP API, the result-pipeline consumer, and (when configured) the
	// agent gRPC transport together; a signal or a failure in any drains all.
	g, gctx := errgroup.WithContext(ctx)
	if asyncEnricher != nil {
		// SCALE-011: background warm pool for flow enrichment cache misses.
		g.Go(func() error { return asyncEnricher.Run(gctx) })
	}

	// On-call/ITSM integration (S33): mirror incidents into PagerDuty/Opsgenie/
	// Slack/Teams/ServiceNow/Jira and sync status back. OFF unless connectors are
	// configured (an outbound connection to the operator's tooling). The dispatcher
	// drives both the incident-opened observer (page + open a ticket) and the
	// server's inbound status-sync webhook + resolve handler. nil when disabled.
	dispatcher, notifyOn := control.BuildDispatcher(cfg, db.Pool(), log)

	// CMDB correlation (S40): read-only CI lookups against the operator's
	// ServiceNow. OFF unless PROBECTL_CMDB_PROVIDER is set. nil when disabled.
	cmdbResolver := control.BuildCMDB(cfg, log)

	// Incident correlation (S17): related signals across planes group into one
	// incident. Alerts feed it via a sink; BGP events via a bus consumer. When
	// on-call/ITSM is configured, an opened incident also pages + opens a ticket.
	var corrOpts []incident.Option
	if notifyOn {
		corrOpts = append(corrOpts, incident.WithObserver(control.NotifyObserver(dispatcher, log)))
		log.Info("on-call/itsm integration enabled", "connectors", len(cfg.NotifyConnectors))
	}
	correlator := control.BuildCorrelator(db.Pool(), cfg.IncidentWindow, log, corrOpts...)
	// Topology dependency graph (S43): the live store behind /v1/topology and
	// the what-if API, fed by eBPF service edges, BGP events, device telemetry
	// (consumer below) and path discoveries (at save time). Engine selection is
	// transparent behind the S30 query API.
	// TENANT-101: registry-backed (tenant, agent) verification for every
	// agent-published bus plane — the payload is never authoritative.
	tenantBinding := pipeline.NewRegistryBinding(db.Pool())

	var topoStore topology.Store
	if cfg.TopologyEngine == "memory" {
		topoStore = topology.NewMemoryStore()
	} else {
		topoStore = topology.NewIndexedStore() // the L/XL dedicated engine
	}
	// ebpfStore (ARCH-008: durable eBPF flow/L7 aggregate store) is built in
	// buildServeStores above and consumed here.
	g.Go(func() error {
		return superviseRestart(gctx, "topology-consumer", log, func(ctx context.Context) error {
			return control.NewTopologyConsumer(resultBus, topoStore, log).
				WithTenantBinding(tenantBinding).
				WithEBPFStore(ebpfStore).
				Run(ctx)
		})
	})
	log.Info("topology graph enabled", "engine", cfg.TopologyEngine, "ebpf_store", cfg.EBPFStoreMode)

	// FinOps egress cost (S44): volume x public pricing over the local flow
	// stream — attribution, chatty-pair detection, budgets. Purely local (no
	// billing-API calls); budget breaches are SIGNALS into incidents.
	costEngine, costOn, err := control.BuildCost(cfg, log)
	if err != nil {
		return err // malformed zone/owner/budget/pricing config fails startup
	}
	if costOn {
		g.Go(func() error {
			return control.NewCostConsumer(resultBus, costEngine, correlator, log).WithTenantBinding(tenantBinding).Run(gctx)
		})
	}

	// Carbon/power estimation (S48): the ESG sibling of the cost engine —
	// same flow stream, same attribution config, energy/carbon ESTIMATES
	// with a served methodology block. Local-only.
	carbonEngine, carbonOn, err := control.BuildCarbon(cfg, log)
	if err != nil {
		return err // malformed attribution config fails startup
	}
	if carbonOn {
		g.Go(func() error {
			// ARCH-020: a sidecar plane restarts on failure instead of killing
			// the whole errgroup (and with it the API + result pipeline).
			return superviseRestart(gctx, "carbon-consumer", log, func(ctx context.Context) error {
				return control.NewCarbonConsumer(resultBus, carbonEngine, log).Run(ctx)
			})
		})
	}

	// SLO engine (S45): OpenSLO definitions evaluated per tenant over the
	// synthetic-result stream; burn-rate breaches are SIGNALS into incidents,
	// and the engine feeds SLO impact into S43 what-if simulations. Built
	// before the API server so /v1/slos serves engine truth (the consumer
	// launches below, beside its SIEM-dependent peers).
	sloEngine, sloOn, err := control.BuildSLO(cfg, log)
	if err != nil {
		return err // malformed SLO definitions fail startup
	}

	// Compliance / segmentation validation (S46): declared policies validated
	// against observed flow + eBPF traffic; violations are SIGNALS into
	// incidents + SIEM. probectl validates — it never enforces. Built before
	// the API server so /v1/compliance serves validator truth.
	complianceEngine, complianceOn, err := control.BuildCompliance(cfg, log)
	if err != nil {
		return err // malformed policy dir fails startup
	}

	// Editions / license (S-T0): load once, fail closed on a configured-but-
	// invalid file; absent = Community (the full core, default-open).
	// Verification is local math against build-time-baked keys — never
	// phone-home. ee/ features gate at the attachEE seam (ee_attach.go) via
	// lic.Has/Mode — S-T1 wired the provider plane there; later S-T/EE
	// sprints add theirs in the same place.
	lic, err := control.BuildLicense(cfg, log)
	if err != nil {
		return err
	}

	// Collective internet-outage view (S47a): public outage feeds (OPT-IN —
	// enabling them makes outbound fetches) + the customer's own vantage
	// points, correlated per tenant. The engine is local-only and on by
	// default; without the IP enricher it degrades honestly (events render,
	// vantage detection and impact correlation report unavailable).
	outageStore, outageRefresher, outageFeedsOn := control.BuildOutageFeeds(cfg, log)
	outageEngine, outageOn := control.BuildOutage(cfg, outageStore, ipEnricher, log)
	if outageFeedsOn {
		g.Go(func() error { return outageRefresher.Run(gctx) })
	}
	// Decode-once fan-out (Sprint 14, SCALE-013): the sidecar result consumers
	// register typed sinks on ONE subscription instead of each re-decoding the
	// results topic under its own group.
	var resultSinks []control.ResultSink
	if outageOn {
		oc := control.NewOutageConsumer(resultBus, outageEngine, correlator, log)
		resultSinks = append(resultSinks, control.ResultSink{Name: "outage-vantage", Fn: oc.SinkResult})
		log.Info("outage view enabled", "feeds", outageFeedsOn, "scope_resolution", ipEnricher != nil)
	}

	// RUM convergence (S47b): real-user beacons (consent-gated, redacted at
	// the edge) joined with synthetic outcomes per host; verdict transitions
	// are SIGNALS into incidents. OFF unless app keys are configured — the
	// beacon ingest is an inbound surface. The consumer joins both topics.
	rumEngine, rumApps, rumOn, err := control.BuildRUM(cfg, log)
	if err != nil {
		return err // a malformed app-key registry fails startup (fail closed)
	}
	if rumOn {
		rc := control.NewRUMConsumer(resultBus, rumEngine, correlator, log)
		resultSinks = append(resultSinks, control.ResultSink{Name: "rum-synthetic", Fn: rc.SinkResult})
		g.Go(func() error { return rc.RunViews(gctx) })
	}

	g.Go(func() error {
		return superviseRestart(gctx, "bgp-incident-consumer", log, func(ctx context.Context) error {
			return control.NewBGPIncidentConsumer(resultBus, correlator, log).Run(ctx)
		})
	})

	// Alerting (S16): evaluate enabled rules over the TSDB, notify channels, and
	// correlate fired alerts into incidents. Disabled gracefully when the TSDB has
	// no in-process query backend. Built before the API server so the active-alert
	// surface (S-FE1) can read the evaluator engine's state.
	var alertEngine *alert.Engine
	alertingActive := false
	if ev, ok := control.BuildAlertEvaluator(db.Pool(), tsdbWriter, alert.ChannelDeps{},
		cfg.AlertEvalInterval, tenancy.DefaultTenantID, control.AlertSink(correlator, log), log); ok {
		alertEngine = ev.Engine()
		alertingActive = true
		g.Go(func() error { ev.Run(gctx); return nil })
	} else {
		// ARCH-002/CORRECT-006: the rules API now surfaces this loudly so the
		// operator isn't lulled into thinking stored rules fire.
		log.Warn("ALERTING INACTIVE: no query backend wired in this profile — stored rules will NOT evaluate")
	}

	// TLS/cert posture inventory (S-FE2): the latest analyzed posture per
	// (tenant, target), bounded per tenant; written by the S27 consumer below
	// and served at /v1/tls/posture.
	tlsPostures := threat.NewPostureStore(0)
	// Threat detections (S-FE3): IOC/NDR matches recorded by the threat
	// consumers below; served at /v1/threat/detections.
	detections := threat.NewDetectionStore(0)
	// Endpoint DEM views (S-FE4): latest WiFi/gateway/last-mile/attribution per
	// endpoint, fed by the endpoint-view consumer; served at /v1/endpoints.
	endpointViews := endpoint.NewSnapshotStore(0)
	// Latest synthetic results (S-FE5): the per-type result detail behind the
	// test-result views; served at /v1/results/latest.
	latestResults := control.NewLatestResults(0)

	// Agent enrollment (Sprint 11): load the issuance service when the CA
	// hierarchy exists; otherwise the enroll routes answer 503 with the init
	// instruction (no silent half-configured trust root).
	enrollSvc, enrollErr := enroll.Load(context.Background(), db.Pool(), log)
	switch {
	case enrollErr == nil:
		log.Info("agent enrollment enabled (SVID issuance active)", "leaf_ttl", enroll.DefaultLeafTTL.String())
	case errors.Is(enrollErr, store.ErrAgentCANotInitialized):
		log.Info("agent enrollment not configured (run: probectl-control agent-ca init)")
	default:
		return fmt.Errorf("load agent enrollment service: %w", enrollErr)
	}

	srv := control.New(cfg, log, db, db.Pool(), pathStore, nil).
		WithDispatcher(dispatcher).
		WithFlowStore(flowStore).
		WithOTelStore(otelStore).
		WithTSDB(tsdbWriter). // Grafana datasource + federation + remote-write (S40)
		WithCMDB(cmdbResolver).
		WithTLSPosture(tlsPostures).
		WithDetections(detections).
		WithEndpointViews(endpointViews).
		WithLatestResults(latestResults).
		WithSecrets(secretsResolver). // backend health at /v1/secrets/health (S41)
		WithTopology(topoStore).      // dependency graph + what-if (S43)
		WithCost(costEngine).         // FinOps summary at /v1/cost/summary (S44)
		WithCarbon(carbonEngine)      // energy/carbon estimates at /v1/carbon (S48)
	if sloOn {
		srv.WithSLO(sloEngine) // SLO statuses at /v1/slos + what-if impact (S45)
	}
	if enrollSvc != nil {
		srv.SetEnrollService(enrollSvc)
	}
	if complianceOn {
		srv.WithCompliance(complianceEngine) // verdicts + evidence at /v1/compliance (S46)
	}
	if outageOn {
		srv.WithOutage(outageEngine) // collective outage view at /v1/outages (S47a)
	}
	if outageFeedsOn {
		srv.WithOutageFeeds(outageRefresher) // feed health + AUP provenance (S47a)
	}
	if rumOn {
		// Beacon ingest at POST /ingest/rum + convergence view at /v1/rum (S47b).
		srv.WithRUM(rumEngine, rumApps, func(ctx context.Context, tenant string, payload []byte) error {
			// Siloed lane routing (S-T2). FAIL CLOSED (RED-006): an unresolved
			// lane drops the beacon (the sender retries) — a siloed tenant's
			// data never silently rides the shared lane.
			t, rerr := tenancy.CurrentRouter().TargetsFor(ctx, tenant)
			if rerr != nil {
				return fmt.Errorf("isolation routing unavailable (fail closed): %w", rerr)
			}
			topic, terr := bus.TopicFor(t.BusNamespace, bus.RUMEventsTopic)
			if terr != nil {
				return terr
			}
			return resultBus.Publish(ctx, topic, []byte(tenant), payload)
		}, cfg.RUMRatePerMin)
	}
	srv.WithLicense(lic) // editions truth at /v1/editions (S-T0)
	// Fairness (S-T7, core): per-tenant ingest bounds + query-cost guards.
	// Deployment defaults come from PROBECTL_FAIRNESS_* (zero = unlimited);
	// per-tenant overrides live in tenant_fairness (set from the provider
	// plane) and are read through the provider role with an async TTL cache
	// — admission never blocks on Postgres. Enforcement protects the pooled
	// platform itself, so it is core in every edition (ratified).
	var fairnessSource fairness.PolicySource
	if db.Pool() != nil {
		fairnessSource = fairness.NewPGStore(db.Pool())
	}
	fairGate := fairness.NewGate(fairness.Policy{
		ResultsPerSec:       cfg.FairnessResultsPerSec,
		FlowEventsPerSec:    cfg.FairnessFlowEventsPerSec,
		IngestBytesPerSec:   cfg.FairnessIngestBytesPerSec,
		DeviceMetricsPerSec: cfg.FairnessDeviceMetricsPerSec,
		OTLPSeriesPerSec:    cfg.FairnessOTLPSeriesPerSec, // SCALE-003
		BurstSeconds:        cfg.FairnessBurstSeconds,
		QueryConcurrency:    cfg.FairnessQueryConcurrency,
		QueriesPerMin:       cfg.FairnessQueriesPerMin,
	}, fairnessSource)
	srv.WithFairness(fairGate)
	srv.WithA2ABroker(a2aBroker) // ARCH-009: session-start API over the broker
	// ARCH-001: load (or first-boot generate) the test-bundle signing key so
	// GET /v1/tests/bundle serves SIGNED bundles agents verify against the
	// build-baked public half. Off when no key file is configured.
	if cfg.TestSyncSigningKeyFile != "" {
		tsPriv, _, _, gerr := crypto.LoadOrGenerateEd25519KeyFile(cfg.TestSyncSigningKeyFile)
		if gerr != nil {
			return fmt.Errorf("testsync signing key: %w", gerr)
		}
		srv.WithTestSyncKey(tsPriv)
		log.Info("central test distribution enabled (signed bundles)", "key_file", cfg.TestSyncSigningKeyFile)
	}
	// ARCH-003: pure in-RAM views (topology, endpoint) fan in per replica using
	// a STABLE per-replica id (hostname/pod name — survives restarts so groups
	// don't sprawl) so every replica builds the complete view and answers
	// coherently. Single-replica/dev (empty/duplicate hostname) keeps the shared
	// group name. Side-effecting consumers keep their shared groups.
	if hn, herr := os.Hostname(); herr == nil && hn != "" {
		control.SetInstanceGroupSuffix(hn)
	}

	// CORRECT-009: expose the pipeline/bus/clock-skew loss counters as gauges.
	registerLossGauges(srv.Metrics(), resultBus, tsdbWriter)
	// Fairness accounting as per-tenant TSDB series (Grafana-federable).
	g.Go(func() error { fairness.RunMetrics(gctx, tsdbWriter, fairGate, 30*time.Second, log); return nil })
	// Self-monitoring (S-EE4): probectl observes probectl — goroutines, mem,
	// uptime, build_info as TSDB series for the self-monitoring dashboard.
	supportStart := time.Now()
	g.Go(func() error { support.RunSelfMetrics(gctx, tsdbWriter, supportStart, 30*time.Second, log); return nil })

	// Multi-region / active-active HA (S-EE2). Inert unless PROBECTL_REGION is
	// set: a single-region deployment keeps writes always-allowed and omits
	// cluster status. With a region configured, the split-brain fence probes
	// the writer (and the read replica, if any) and pauses API writes during a
	// failover while reads + telemetry keep flowing.
	if cfg.Region != "" {
		topo := cluster.Topology{
			Region: cfg.Region, Regions: cfg.Regions, Residency: cfg.Residency,
			ReplicationMode: cluster.ReplicationMode(cfg.ReplicationMode),
			RPOSeconds:      cfg.RPOSeconds, RTOSeconds: cfg.RTOSeconds,
		}
		var readProbe cluster.Prober
		if db.ReadPool() != db.Pool() {
			readProbe = cluster.NewPGProber(db.ReadPool())
		}
		clusterMgr := cluster.NewManager(topo, cluster.NewPGProber(db.Pool()), readProbe)
		srv.WithCluster(clusterMgr)
		g.Go(func() error { clusterMgr.Run(gctx, 5*time.Second); return nil })
		g.Go(func() error { cluster.RunMetrics(gctx, tsdbWriter, clusterMgr, 30*time.Second, log); return nil })
		log.Info("multi-region HA active (S-EE2)", "region", cfg.Region,
			"regions", cfg.Regions, "replication", cfg.ReplicationMode, "read_replica", readProbe != nil)
	}
	// Per-tenant lifecycle (S-T5, core): export / retention / verifiable
	// erasure with attestation. The object store is agent-side (browser
	// artifacts), so the control plane's engine runs without one — recorded
	// honestly per store in every attestation. The daily sweeper enforces
	// per-tenant flow retention.
	lifeEngine := tenantlife.NewWithBackupRetention(db.Pool(), flowStore, nil, tsdbWriter,
		func(ctx context.Context, actor, action, target string, data map[string]any) error {
			_, err := audit.ProviderAppend(ctx, db.Pool(), actor, action, target, data)
			return err
		}, cfg.BackupRetentionNote, cfg.BackupRetentionDays, log)
	// U-027: erasure coverage for the path store + topology graph; the
	// attestation enumerates them (or records "store not deployed").
	if pd, ok := pathStore.(tenantlife.PathDeleter); ok {
		lifeEngine.WithPaths(pd)
	}
	if td, ok := topoStore.(tenantlife.TopologyDeleter); ok {
		lifeEngine.WithTopology(td)
	}
	// TENANT-008: erasure coverage for the OTLP trace/log store — externally-
	// ingested traces+logs are tenant PII; the attestation enumerates the
	// "otel" store (count-verified) or records "store not deployed".
	if od, ok := otelStore.(tenantlife.OtelDeleter); ok {
		lifeEngine.WithOtel(od)
	}
	// TENANT-002: erasure coverage for the eBPF L7 edge store — workload edges,
	// dest ports and L7 protocols are tenant telemetry; the attestation
	// enumerates the "ebpf" store (count-verified) or records "store not
	// deployed". Previously this whole plane survived offboarding while the
	// attestation could still report Complete:true.
	if ed, ok := ebpfStore.(tenantlife.EBPFDeleter); ok {
		lifeEngine.WithEBPF(ed)
	}
	srv.WithTenantLife(lifeEngine)
	g.Go(func() error { lifeEngine.RunRetention(gctx, 24*time.Hour); return nil })
	// U-041: WORM export of the provider audit chain — signed segments into
	// an (object-locked) store, chain-verified every cycle.
	if cfg.AuditWORMDir != "" {
		wormStore, werr := objectstore.NewFS(cfg.AuditWORMDir)
		if werr != nil {
			return fmt.Errorf("audit worm store: %w", werr)
		}
		// KEYS-002 (D2): resolve a PERSISTED signing key — env base64 wins, else a
		// key file (generated + persisted on first boot); fail closed if WORM
		// export is on but no key resolves (never an ephemeral per-boot key, which
		// would break cross-restart verification of the chain).
		wormPriv, wormPub, wormKeyGen, kerr := audit.ResolveWormSigningKey(cfg.WormSigningKey, cfg.WormSigningKeyFile, cfg.RequireAtRestEncryption)
		if kerr != nil {
			return fmt.Errorf("audit worm signing key: %w", kerr)
		}
		if wormKeyGen {
			log.Warn("GENERATED a new WORM audit signing key — back this file up like any key material; losing it forfeits cross-restart verification of the exported chain",
				"key_file", cfg.WormSigningKeyFile)
		}
		worm, werr := audit.NewWormExporterPG(db.Pool(), wormStore, wormPriv, wormPub, log)
		if werr != nil {
			return fmt.Errorf("audit worm exporter: %w", werr)
		}
		g.Go(func() error { worm.Run(gctx, cfg.AuditWORMInterval); return nil })
		log.Info("audit WORM export enabled", "dir", cfg.AuditWORMDir, "interval", cfg.AuditWORMInterval.String())
	}
	// Tenant lifecycle gate (S-T1): users of suspended/offboarded tenants are
	// rejected at the API; data and ingestion are untouched.
	srv.WithTenantStatus(control.NewTenantStatusCache(db.Pool(), 0))
	// The ee attach seam (S-T1+): licensed commercial features are constructed
	// and mounted here — and ONLY here. The core-only build (-tags
	// probectl_core) compiles the no-op twin, proving core stands alone.
	if err := attachEE(gctx, srv, cfg, log, lic, db.Pool(), latestResults, flowStore, pathCH, ebpfStore, otelStore, lifeEngine, secretsResolver.Resolve, fairGate, topoStore); err != nil {
		return err
	}
	if alertEngine != nil {
		// Active alerts + silence/ack (S-FE1) read engine truth, tenant-keyed.
		srv.WithAlertState(tenancy.DefaultTenantID.String(), alertEngine)
	}
	// ARCH-002: tell the rules API whether evaluation is actually live so it can
	// warn instead of silently accepting dead rules.
	srv.WithAlertingActive(alertingActive)
	g.Go(func() error { return srv.Run(gctx) })
	// Siloed bus lanes (S-T2): subscribe the result pipeline to every siloed/
	// hybrid tenant's namespaced topics known at startup (the shared lanes stay
	// subscribed regardless; a tenant siloed after boot is picked up on the
	// next restart). Pooled deployments resolve zero namespaces.
	busNamespaces, nsErr := tenancy.CurrentRouter().BusNamespaces(gctx)
	if nsErr != nil {
		log.Warn("isolation: bus namespaces unavailable; consuming shared lanes only", "error", nsErr.Error())
	} else if len(busNamespaces) > 0 {
		log.Info("isolation: consuming namespaced result lanes", "namespaces", busNamespaces)
	}
	// TENANT-101: the lane -> tenant map makes namespaced lanes the
	// AUTHORITATIVE tenant source; the registry binding makes the payload's
	// (tenant, agent) pair verifiable on shared lanes. Both fail closed.
	nsTenants, ntErr := tenancy.CurrentRouter().BusNamespaceTenants(gctx)
	if ntErr != nil {
		log.Warn("isolation: namespace-tenant map unavailable", "error", ntErr.Error())
	}
	// ARCH-002: the CORE ingest consumers (result/flow/device/endpoint) and the
	// result-fan are SUPERVISED — a transient broker/registry fault while
	// (re)establishing a subscription restarts just that consumer instead of
	// cancelling the shared errgroup and taking the API + every plane down. Only
	// srv.Run and migrations stay fatal by design (if they can't run, the process
	// SHOULD exit). Steady-state handler/store errors are already absorbed by the
	// per-consumer retry/DLQ, so the supervised trigger is the subscribe path.
	g.Go(func() error {
		return superviseRestart(gctx, "result-pipeline", log, func(ctx context.Context) error {
			return pipeline.NewConsumer(resultBus, ingestWriter, pipeline.DefaultGroup, log).
				WithNamespaces(busNamespaces).
				WithNamespaceTenants(nsTenants).
				WithTenantBinding(tenantBinding).                   // TENANT-101: endpoint lane verified
				WithStrictTenantLanes(cfg.IngestStrictTenantLanes). // WIRE-001
				WithFairness(fairGate).
				WithCardinalityCaps(cfg.IngestMaxSeriesPerAgent, cfg.IngestMaxSeriesPerTenant). // U-017
				Run(ctx)
		})
	})
	// Flow pipeline (S38): probectl.flow.events -> verify tenant -> enrich -> flow store.
	g.Go(func() error {
		return superviseRestart(gctx, "flow-pipeline", log, func(ctx context.Context) error {
			return pipeline.NewFlowConsumer(resultBus, flowStore, flowEnricher, log).
				WithTenantBinding(tenantBinding).
				WithNamespaceTenants(nsTenants).
				WithStrictTenantLanes(cfg.IngestStrictTenantLanes). // WIRE-001
				WithFairness(fairGate).Run(ctx)
		})
	})
	// Device pipeline (S39): probectl.device.metrics -> verify tenant -> TSDB.
	g.Go(func() error {
		return superviseRestart(gctx, "device-pipeline", log, func(ctx context.Context) error {
			return pipeline.NewDeviceConsumer(resultBus, ingestWriter, log).
				WithFairness(fairGate). // SCALE-005: device plane bounded like every plane
				WithTenantBinding(tenantBinding).
				WithNamespaceTenants(nsTenants).
				WithStrictTenantLanes(cfg.IngestStrictTenantLanes). // WIRE-001
				Run(ctx)
		})
	})
	// Endpoint DEM view (S-FE4): probectl.endpoint.results -> snapshot store.
	g.Go(func() error {
		return superviseRestart(gctx, "endpoint-view", log, func(ctx context.Context) error {
			return control.NewEndpointViewConsumer(resultBus, endpointViews, log).Run(ctx)
		})
	})
	// Latest-result view (S-FE5): probectl.network.results -> latest-result store.
	resultSinks = append(resultSinks, control.ResultSink{
		Name: "result-view", Fn: control.NewResultViewConsumer(resultBus, latestResults, log).SinkResult})

	// SIEM export (S32): forward the audit stream + threat-plane signals to the
	// SOC's SIEM. OFF unless configured (an outbound connection to the operator's
	// endpoint). One delivery worker drains a bounded buffer with retry; a poller
	// streams each tenant's audit log from a durable per-tenant cursor so a restart
	// neither drops nor re-floods. siemFwd is nil when disabled (WithSIEM no-op).
	siemFwd, siemOn := control.BuildSIEM(cfg, log)
	if siemOn {
		g.Go(func() error { return siemFwd.Run(gctx) })
		g.Go(func() error {
			return control.NewSIEMAuditPoller(db.Pool(), siemFwd, cfg.SIEMRedactKeys, cfg.SIEMPollInterval, log).Run(gctx)
		})
		log.Info("siem export enabled", "preset", cfg.SIEMPreset, "poll", cfg.SIEMPollInterval)
	}

	// Threat-intel enrichment (S28): build the shared IOC store + refresher. OFF
	// unless configured (enabling it makes outbound feed fetches). The store
	// enriches BOTH the TLS/cert analyzer (malicious cert/JA3) and an IP/host
	// consumer over network results; matches are confidence-scored signals.
	iocStore, iocRefresher, intelOn := control.BuildThreatIntel(cfg, log)
	if intelOn {
		g.Go(func() error { return iocRefresher.Run(gctx) })
		ioc := control.NewIOCConsumer(resultBus, correlator, iocStore, log).
			WithSIEM(siemFwd).
			WithDetections(detections) // triage feed (S-FE3)
		resultSinks = append(resultSinks, control.ResultSink{Name: "threat-intel-ip", Fn: ioc.SinkResult})
		log.Info("threat-intel enrichment enabled", "refresh", cfg.ThreatIntelRefresh)
	}

	// SLO + compliance consumers (engines built above, before the API server).
	if sloOn {
		g.Go(func() error {
			return superviseRestart(gctx, "slo-consumer", log, func(ctx context.Context) error {
				return control.NewSLOConsumer(resultBus, sloEngine, correlator, log).
					WithNamespaceTenants(nsTenants). // CORRECT-005: evaluate SLOs for siloed tenants too
					Run(ctx)
			})
		})
	}
	if complianceOn {
		g.Go(func() error {
			return superviseRestart(gctx, "compliance-consumer", log, func(ctx context.Context) error {
				return control.NewComplianceConsumer(resultBus, complianceEngine, correlator, log).
					WithSIEM(siemFwd).
					WithTenantBinding(tenantBinding).
					Run(ctx)
			})
		})
	}

	// NDR-lite behavioral detection (S42): DGA/exfil/beaconing/egress/lateral
	// over the DNS/flow/eBPF streams already arriving here. Purely local (no
	// outbound calls); detections are confidence-scored SIGNALS exported to
	// incidents + triage + SIEM — never blocks (guardrail 9). The live
	// topology store excludes known service relationships from lateral
	// detection (S43 closes the S42 seam).
	ndrEngine, ndrOn, err := control.BuildNDR(cfg, intelSourceOrNil(iocStore), topoStore, log)
	if err != nil {
		return err // malformed rules dir fails startup (fail closed)
	}
	if ndrOn {
		ndrc := control.NewNDRConsumer(resultBus, ndrEngine, correlator, log).
			WithTenantBinding(tenantBinding). // ARCH-012: verify flow/eBPF tenants before raising detections
			WithFairness(fairGate).           // SCALE-005: bound this 2nd flow/eBPF consumer group per tenant
			WithSIEM(siemFwd).
			WithDetections(detections)
		resultSinks = append(resultSinks, control.ResultSink{Name: "ndr-dns", Fn: ndrc.SinkResult})
		g.Go(func() error { return ndrc.RunFlowLanes(gctx) })
	}

	// TLS/cert posture (S27): analyze captured TLS from HTTPS synthetic results
	// into threat-plane incidents (expiry/weakness + a trustctl renewal handoff),
	// reusing already-captured TLS — never re-handshaking. When threat-intel is on,
	// the analyzer also scores the leaf cert SHA1 + JA3 against IOCs (S28).
	tlsAnalyzer := control.BuildTLSAnalyzer(cfg)
	if iocStore != nil {
		tlsAnalyzer.WithIntel(iocStore)
	}
	tlsc := control.NewTLSPostureConsumer(resultBus, correlator, tlsAnalyzer, log).
		WithSIEM(siemFwd).
		WithPostureStore(tlsPostures). // certificate inventory (S-FE2)
		WithDetections(detections)     // triage feed (S-FE3)
	resultSinks = append(resultSinks, control.ResultSink{Name: "tls-posture", Fn: tlsc.SinkResult})
	// ONE subscription, ONE decode, every sink (SCALE-013).
	resultFan := control.NewResultFan(resultBus, log, resultSinks...)
	// ARCH-002: the result-fan carries every result-derived sink (latest-result
	// view, threat-intel, TLS posture, NDR, …) on ONE subscription — supervise it
	// so a subscribe-path fault restarts the fan, not the whole process.
	g.Go(func() error {
		return superviseRestart(gctx, "result-fan", log, func(ctx context.Context) error {
			return resultFan.Run(ctx)
		})
	})

	if cfg.AgentTransportEnabled() {
		grpcSrv, err := agenttransport.New(cfg.AgentTLSCertFile, cfg.AgentTLSKeyFile, cfg.AgentTLSCAFile, db.Pool(), resultBus, a2aBroker, log)
		if err != nil {
			return fmt.Errorf("agent transport: %w", err)
		}
		// Version-skew policy (S34): reject agents outside the N/N-1 window (or an
		// explicit floor) at registration.
		grpcSrv.WithVersionPolicy(lifecycle.Policy{Window: cfg.AgentSkewWindow, Min: cfg.AgentMinVersion})
		// Sprint 12 (WIRE-003 residual): FEED the handshake deny-list. Boot
		// loads persisted revocations; the API pushes live; the refresher
		// (30s) picks up CLI-side revocations and keeps restarts converged.
		if enrollSvc != nil {
			reload := func() {
				serials, ids, rerr := enrollSvc.ListRevoked(gctx)
				if rerr != nil {
					log.Error("revocation reload failed (keeping the previous deny-list)", "error", rerr.Error())
					return
				}
				grpcSrv.RevocationList().Replace(serials, ids)
			}
			reload()
			srv.SetAgentRevocationPush(func(serials, ids []string) {
				for _, s := range serials {
					grpcSrv.RevocationList().RevokeSerial(s)
				}
				for _, id := range ids {
					grpcSrv.RevocationList().RevokeID(id)
				}
			})
			g.Go(func() error {
				t := time.NewTicker(30 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-gctx.Done():
						return nil
					case <-t.C:
						reload()
					}
				}
			})
		}
		g.Go(func() error { return grpcSrv.Serve(gctx, cfg.AgentGRPCAddr) })
	}

	// OTLP receiver (S22): TLS-only, authenticated, tenant-scoped ingest of
	// external OTLP. Ingested metrics are tenant-tagged and published to the bus.
	if cfg.OTLPEnabled() {
		tlsCfg, err := crypto.ServerTLSConfig(cfg.OTLPTLSCertFile, cfg.OTLPTLSKeyFile)
		if err != nil {
			return fmt.Errorf("otlp tls: %w", err)
		}
		// ARCH-001 (Sprint 22): all THREE OTLP signals — metrics, traces,
		// logs — are received, tenant-scoped, published per-signal, consumed,
		// stored, and queryable (/v1/otlp/*).
		sinks := otlp.Sinks{
			Metrics: otlp.NewBusSink(func(ctx context.Context, tenant string, payload []byte) error {
				return resultBus.Publish(ctx, bus.OTLPMetricsTopic, []byte(tenant), payload)
			}),
			Traces: otlp.NewBusTraceSink(func(ctx context.Context, tenant string, payload []byte) error {
				return resultBus.Publish(ctx, bus.OTLPTracesTopic, []byte(tenant), payload)
			}),
			Logs: otlp.NewBusLogSink(func(ctx context.Context, tenant string, payload []byte) error {
				return resultBus.Publish(ctx, bus.OTLPLogsTopic, []byte(tenant), payload)
			}),
		}
		otlpSrv, err := otlp.NewServer(
			otlp.ServerConfig{GRPCAddr: cfg.OTLPGRPCAddr, HTTPAddr: cfg.OTLPHTTPAddr},
			tlsCfg, otlp.NewTokenAuthenticator(cfg.OTLPTokens), sinks, log)
		if err != nil {
			return fmt.Errorf("otlp receiver: %w", err)
		}
		// ARCH-002: supervise the OTLP receiver — an ingest listener failure
		// (e.g. a transient bind/TLS fault) restarts the receiver instead of
		// killing the whole control plane.
		g.Go(func() error {
			return superviseRestart(gctx, "otlp-receiver", log, func(ctx context.Context) error {
				return otlpSrv.Run(ctx)
			})
		})
		// SCALE-010 + ARCH-001: every topic has a CONSUMER — metrics land in
		// the TSDB; traces + logs land in the otelstore.
		// SCALE-003/ARCH-002: each consumer retries + dead-letters store-write
		// failures; .WithMetrics surfaces the DLQ/drop counters at /metrics.
		// ARCH-002: the consumers are supervised too (subscribe-path faults).
		g.Go(func() error {
			return superviseRestart(gctx, "otlp-metrics-consumer", log, func(ctx context.Context) error {
				return pipeline.NewOTLPConsumer(resultBus, ingestWriter, log).WithMetrics(srv.Metrics()).WithFairness(fairGate).WithCardinalityCaps(cfg.IngestMaxSeriesPerTenant).Run(ctx) // SCALE-003
			})
		})
		// ARCH-007: config-driven OTLP export — forward ingested metrics on to an
		// external collector when an endpoint is configured (the dormant exporter
		// is now live). A failed forward redelivers; never a silent drop.
		if cfg.OTLPExportEnabled() {
			exp, eerr := buildOTLPExporter(cfg)
			if eerr != nil {
				return fmt.Errorf("otlp export: %w", eerr)
			}
			g.Go(func() error {
				return superviseRestart(gctx, "otlp-export", log, func(ctx context.Context) error {
					return pipeline.NewOTLPExportConsumer(resultBus, exp, log).Run(ctx)
				})
			})
			// ARCH-003: traces + logs are first-class export too — drain their
			// ingest topics and re-export to the external collector, so a
			// customer's own trace/log backend receives them (not ingest-only).
			g.Go(func() error {
				return superviseRestart(gctx, "otlp-trace-export", log, func(ctx context.Context) error {
					return pipeline.NewOTLPTraceExportConsumer(resultBus, exp, log).Run(ctx)
				})
			})
			g.Go(func() error {
				return superviseRestart(gctx, "otlp-log-export", log, func(ctx context.Context) error {
					return pipeline.NewOTLPLogExportConsumer(resultBus, exp, log).Run(ctx)
				})
			})
			log.Info("otlp export enabled (metrics+traces+logs)", "endpoint", cfg.OTLPExportEndpoint, "protocol", cfg.OTLPExportProtocol)
		}
		// ARCH-002: the trace + log ingest consumers are supervised too.
		g.Go(func() error {
			return superviseRestart(gctx, "otlp-traces-consumer", log, func(ctx context.Context) error {
				return pipeline.NewOTLPTraceConsumer(resultBus, otelStore, log).WithMetrics(srv.Metrics()).WithFairness(fairGate).Run(ctx) // SCALE-003
			})
		})
		g.Go(func() error {
			return superviseRestart(gctx, "otlp-logs-consumer", log, func(ctx context.Context) error {
				return pipeline.NewOTLPLogConsumer(resultBus, otelStore, log).WithMetrics(srv.Metrics()).WithFairness(fairGate).Run(ctx) // SCALE-003
			})
		})
	}

	// MCP server (S25): the Model Context Protocol HTTP transport — TLS + bearer-
	// authenticated, tenant- + RBAC-scoped read tools. Off unless configured.
	if cfg.MCPEnabled() {
		tlsCfg, err := crypto.ServerTLSConfig(cfg.MCPTLSCertFile, cfg.MCPTLSKeyFile)
		if err != nil {
			return fmt.Errorf("mcp tls: %w", err)
		}
		mcpSrv := control.NewMCPServer(cfg, log, db.Pool(), pathStore, cfg.MCPRatePerMin, fairGate, srv.RemediationService())
		handler := mcpSrv.HTTPHandler(control.NewMCPAuthenticator(db.Pool()))
		g.Go(func() error { return serveMCPHTTP(gctx, cfg.MCPHTTPAddr, tlsCfg, handler, log) })
	}

	return g.Wait()
}

// (WIRE-005: the bespoke loadServerTLS is gone — every probectl listener
// takes crypto.ServerTLSConfig, the ONE hardened policy: TLS 1.3 floor.)

func runMigrations(ctx context.Context, db *store.DB, log *slog.Logger) error {
	applied, err := migrate.New(migrations.FS, log).Apply(ctx, db.Pool())
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	if len(applied) == 0 {
		log.Info("database schema already up to date")
	} else {
		log.Info("migrations applied", "count", len(applied), "versions", applied)
	}
	return nil
}

// intelSourceOrNil adapts the optional IOC store to the engine's seam: a nil
// *IOCStore must become a nil INTERFACE (not a typed-nil) so the engine's
// nil checks behave.
func intelSourceOrNil(s *opendata.IOCStore) threat.IntelSource {
	if s == nil {
		return nil
	}
	return s
}

// loopbackOnly reports whether addr binds exclusively to a loopback
// interface. An empty host (":8080") or a wildcard (0.0.0.0 / ::) binds every
// interface and is NOT loopback — dev auth refuses it (RED-001).
func loopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
