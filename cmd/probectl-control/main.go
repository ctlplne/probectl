// Command probectl-control is the probectl control-plane API server.
//
// Subcommands:
//
//	probectl-control [serve]   run the stateless HTTP API server (default)
//	probectl-control migrate   apply database migrations and exit
//	probectl-control gen-cert  write a self-signed TLS cert (HTTPS quickstart)
//	probectl-control version   print build metadata and exit
//
// Configuration is read from PROBECTL_-prefixed environment variables
// (see docs/configuration.md).
package main

import (
	"context"
	"crypto/tls"
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
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/lifecycle"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/objectstore"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/otel/otlp"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/secrets"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/support"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantcrypto"
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
	switch cmd {
	case "version", "-version", "--version":
		fmt.Println("probectl-control", version.Get())
		return nil
	case "gen-cert":
		// Self-signed TLS cert for the HTTPS-by-default quickstart; no DB needed.
		return genCert(os.Args[2:])
	case "support-bundle":
		// S-EE4: offline, secret-stripped diagnostics bundle.
		return supportBundle(os.Args[2:])
	case "serve", "migrate", "mcp-stdio", "mcp-token", "scim-token":
		// fall through to the configured path below
	default:
		return fmt.Errorf("unknown command %q (want: serve | migrate | mcp-stdio | mcp-token | scim-token | gen-cert | support-bundle | version)", cmd)
	}

	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	// S41: integration credentials (OIDC client secret, CMDB, AI model, SIEM,
	// webhook/connector secrets) may be SECRET REFERENCES — resolve them through
	// the backends configured in the environment before anything consumes them.
	// Plain values pass through; any resolution failure aborts startup (fail
	// closed — never run with a partially-resolved credential set).
	secretsResolver, err := secrets.FromEnv(0)
	if err != nil {
		return fmt.Errorf("secret backends: %w", err)
	}
	if err := cfg.ResolveSecretRefs(context.Background(), secretsResolver.Resolve); err != nil {
		return err
	}
	// S-T6: install the deployment envelope as the at-rest sealer for
	// sensitive tenant-owned values (alert channel secrets, ...). Keyless dev
	// deployments run passthrough; the licensed byok build replaces the
	// PRIMARY with the per-tenant keyring at the attach seam — this dv1
	// sealer stays registered as an opener, so existing rows keep decrypting.
	if cfg.EnvelopeKey != "" {
		sealer, err := tenantcrypto.NewEnvelopeSealer(cfg.EnvelopeKeyID, cfg.EnvelopeKey)
		if err != nil {
			return fmt.Errorf("envelope sealer: %w", err)
		}
		tenantcrypto.SetPrimary(sealer)
	}
	// mcp-stdio uses stdout for its JSON-RPC channel, so its logs go to stderr.
	logOut := os.Stdout
	if cmd == "mcp-stdio" {
		logOut = os.Stderr
	}
	log := logging.New(logOut, cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(log)

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

	switch cmd {
	case "migrate":
		return runMigrations(context.Background(), db, log)
	case "mcp-stdio":
		return runMCPStdio(cfg, log, db)
	case "mcp-token":
		return runMCPToken(log, db, os.Args[2:])
	case "scim-token":
		return runSCIMToken(log, db, os.Args[2:])
	}

	if cfg.MigrateOnBoot {
		if err := runMigrations(context.Background(), db, log); err != nil {
			return err
		}
	}

	log.Info("starting probectl-control", "version", version.Get().Version, "config", cfg)

	// Result pipeline: a message bus that the control plane consumes and writes
	// to the TSDB. The bus is shared with the agent transport (the publisher).
	memOpts := []bus.MemoryOption{bus.WithBuffer(cfg.BusMemoryBuffer)}
	if cfg.BusMemoryOverflow == "drop" {
		memOpts = append(memOpts, bus.WithOverflowDrop())
	}
	resultBus, err := bus.New(cfg.BusMode, cfg.BusBrokers, cfg.BusSecurity(), memOpts...)
	if err != nil {
		return fmt.Errorf("result bus: %w", err)
	}
	defer resultBus.Close()
	tsdbWriter, err := tsdb.NewWithLimits(cfg.TSDBMode, cfg.TSDBURL, cfg.TSDBMemoryRetention, int64(cfg.TSDBMemoryMaxBytes)) // U-018 bounds
	if err != nil {
		return fmt.Errorf("tsdb: %w", err)
	}
	defer tsdbWriter.Close()

	pathStore, err := pathstore.New(cfg.PathStoreMode, cfg.PathStoreURL)
	if err != nil {
		return fmt.Errorf("path store: %w", err)
	}
	defer pathStore.Close()

	// Flow analytics store (S38): where NetFlow/IPFIX/sFlow records land
	// (ClickHouse at volume; memory in the lightweight deploy) and the
	// /v1/flows/* views are served from.
	flowStore, err := flowstore.New(cfg.FlowStoreMode, cfg.FlowStoreURL, cfg.FlowRetentionDays)
	if err != nil {
		return fmt.Errorf("flow store: %w", err)
	}
	defer flowStore.Close()

	// ASN/geo enrichment for flows (S15 via S38): OPT-IN — Team Cymru is an
	// outbound DNS dependency, so it stays off unless explicitly enabled
	// (no-phone-home guardrail). Device-asserted AS numbers always flow through.
	// The same enricher instance powers the outage view's IP→scope join (S47a).
	var flowEnricher pipeline.FlowEnricher
	var ipEnricher *opendata.Enricher
	if cfg.FlowEnrichASN {
		en := opendata.NewEnricher(log)
		en.Register(opendata.NewCymru(net.DefaultResolver))
		flowEnricher = en
		ipEnricher = en
		log.Info("flow ASN enrichment enabled", "source", "team-cymru")
	}

	// Brokers agent-to-agent measurement sessions; sessions are started by the
	// test API in a later sprint.
	a2aBroker := a2a.NewBroker()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Run the HTTP API, the result-pipeline consumer, and (when configured) the
	// agent gRPC transport together; a signal or a failure in any drains all.
	g, gctx := errgroup.WithContext(ctx)

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
	g.Go(func() error {
		return control.NewTopologyConsumer(resultBus, topoStore, log).WithTenantBinding(tenantBinding).Run(gctx)
	})
	log.Info("topology graph enabled", "engine", cfg.TopologyEngine)

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
			return control.NewCarbonConsumer(resultBus, carbonEngine, log).Run(gctx)
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
	if outageOn {
		g.Go(func() error {
			return control.NewOutageConsumer(resultBus, outageEngine, correlator, log).Run(gctx)
		})
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
		g.Go(func() error {
			return control.NewRUMConsumer(resultBus, rumEngine, correlator, log).Run(gctx)
		})
	}

	g.Go(func() error {
		return control.NewBGPIncidentConsumer(resultBus, correlator, log).Run(gctx)
	})

	// Alerting (S16): evaluate enabled rules over the TSDB, notify channels, and
	// correlate fired alerts into incidents. Disabled gracefully when the TSDB has
	// no in-process query backend. Built before the API server so the active-alert
	// surface (S-FE1) can read the evaluator engine's state.
	var alertEngine *alert.Engine
	if ev, ok := control.BuildAlertEvaluator(db.Pool(), tsdbWriter, alert.ChannelDeps{},
		cfg.AlertEvalInterval, tenancy.DefaultTenantID, control.AlertSink(correlator, log), log); ok {
		alertEngine = ev.Engine()
		g.Go(func() error { ev.Run(gctx); return nil })
	} else {
		log.Info("alert evaluation disabled (no in-process TSDB query backend in this mode)")
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

	srv := control.New(cfg, log, db, db.Pool(), pathStore, nil).
		WithDispatcher(dispatcher).
		WithFlowStore(flowStore).
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
		ResultsPerSec:     cfg.FairnessResultsPerSec,
		FlowEventsPerSec:  cfg.FairnessFlowEventsPerSec,
		IngestBytesPerSec: cfg.FairnessIngestBytesPerSec,
		BurstSeconds:      cfg.FairnessBurstSeconds,
		QueryConcurrency:  cfg.FairnessQueryConcurrency,
		QueriesPerMin:     cfg.FairnessQueriesPerMin,
	}, fairnessSource)
	srv.WithFairness(fairGate)
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
	lifeEngine := tenantlife.New(db.Pool(), flowStore, nil, tsdbWriter,
		func(ctx context.Context, actor, action, target string, data map[string]any) error {
			_, err := audit.ProviderAppend(ctx, db.Pool(), actor, action, target, data)
			return err
		}, cfg.BackupRetentionNote, log)
	// U-027: erasure coverage for the path store + topology graph; the
	// attestation enumerates them (or records "store not deployed").
	if pd, ok := pathStore.(tenantlife.PathDeleter); ok {
		lifeEngine.WithPaths(pd)
	}
	if td, ok := topoStore.(tenantlife.TopologyDeleter); ok {
		lifeEngine.WithTopology(td)
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
		worm, werr := audit.NewWormExporterPG(db.Pool(), wormStore, log)
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
	if err := attachEE(gctx, srv, cfg, log, lic, db.Pool(), latestResults, flowStore, lifeEngine, secretsResolver.Resolve, fairGate, topoStore); err != nil {
		return err
	}
	if alertEngine != nil {
		// Active alerts + silence/ack (S-FE1) read engine truth, tenant-keyed.
		srv.WithAlertState(tenancy.DefaultTenantID.String(), alertEngine)
	}
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
	g.Go(func() error {
		return pipeline.NewConsumer(resultBus, tsdbWriter, pipeline.DefaultGroup, log).
			WithNamespaces(busNamespaces).
			WithNamespaceTenants(nsTenants).
			WithTenantBinding(tenantBinding). // TENANT-101: endpoint lane verified
			WithFairness(fairGate).
			WithCardinalityCaps(cfg.IngestMaxSeriesPerAgent, cfg.IngestMaxSeriesPerTenant). // U-017
			Run(gctx)
	})
	// Flow pipeline (S38): probectl.flow.events -> verify tenant -> enrich -> flow store.
	g.Go(func() error {
		return pipeline.NewFlowConsumer(resultBus, flowStore, flowEnricher, log).
			WithTenantBinding(tenantBinding).
			WithNamespaceTenants(nsTenants).
			WithFairness(fairGate).Run(gctx)
	})
	// Device pipeline (S39): probectl.device.metrics -> verify tenant -> TSDB.
	g.Go(func() error {
		return pipeline.NewDeviceConsumer(resultBus, tsdbWriter, log).
			WithTenantBinding(tenantBinding).
			WithNamespaceTenants(nsTenants).
			Run(gctx)
	})
	// Endpoint DEM view (S-FE4): probectl.endpoint.results -> snapshot store.
	g.Go(func() error { return control.NewEndpointViewConsumer(resultBus, endpointViews, log).Run(gctx) })
	// Latest-result view (S-FE5): probectl.network.results -> latest-result store.
	g.Go(func() error { return control.NewResultViewConsumer(resultBus, latestResults, log).Run(gctx) })

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
		g.Go(func() error {
			return control.NewIOCConsumer(resultBus, correlator, iocStore, log).
				WithSIEM(siemFwd).
				WithDetections(detections). // triage feed (S-FE3)
				Run(gctx)
		})
		log.Info("threat-intel enrichment enabled", "refresh", cfg.ThreatIntelRefresh)
	}

	// SLO + compliance consumers (engines built above, before the API server).
	if sloOn {
		g.Go(func() error {
			return control.NewSLOConsumer(resultBus, sloEngine, correlator, log).Run(gctx)
		})
	}
	if complianceOn {
		g.Go(func() error {
			return control.NewComplianceConsumer(resultBus, complianceEngine, correlator, log).
				WithSIEM(siemFwd).
				WithTenantBinding(tenantBinding).
				Run(gctx)
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
		g.Go(func() error {
			return control.NewNDRConsumer(resultBus, ndrEngine, correlator, log).
				WithSIEM(siemFwd).
				WithDetections(detections).
				Run(gctx)
		})
	}

	// TLS/cert posture (S27): analyze captured TLS from HTTPS synthetic results
	// into threat-plane incidents (expiry/weakness + a trustctl renewal handoff),
	// reusing already-captured TLS — never re-handshaking. When threat-intel is on,
	// the analyzer also scores the leaf cert SHA1 + JA3 against IOCs (S28).
	tlsAnalyzer := control.BuildTLSAnalyzer(cfg)
	if iocStore != nil {
		tlsAnalyzer.WithIntel(iocStore)
	}
	g.Go(func() error {
		return control.NewTLSPostureConsumer(resultBus, correlator, tlsAnalyzer, log).
			WithSIEM(siemFwd).
			WithPostureStore(tlsPostures). // certificate inventory (S-FE2)
			WithDetections(detections).    // triage feed (S-FE3)
			Run(gctx)
	})

	if cfg.AgentTransportEnabled() {
		grpcSrv, err := agenttransport.New(cfg.AgentTLSCertFile, cfg.AgentTLSKeyFile, cfg.AgentTLSCAFile, db.Pool(), resultBus, a2aBroker, log)
		if err != nil {
			return fmt.Errorf("agent transport: %w", err)
		}
		// Version-skew policy (S34): reject agents outside the N/N-1 window (or an
		// explicit floor) at registration.
		grpcSrv.WithVersionPolicy(lifecycle.Policy{Window: cfg.AgentSkewWindow, Min: cfg.AgentMinVersion})
		g.Go(func() error { return grpcSrv.Serve(gctx, cfg.AgentGRPCAddr) })
	}

	// OTLP receiver (S22): TLS-only, authenticated, tenant-scoped ingest of
	// external OTLP. Ingested metrics are tenant-tagged and published to the bus.
	if cfg.OTLPEnabled() {
		tlsCfg, err := loadServerTLS(cfg.OTLPTLSCertFile, cfg.OTLPTLSKeyFile)
		if err != nil {
			return fmt.Errorf("otlp tls: %w", err)
		}
		sink := otlp.NewBusSink(func(ctx context.Context, tenant string, payload []byte) error {
			return resultBus.Publish(ctx, bus.OTLPMetricsTopic, []byte(tenant), payload)
		})
		otlpSrv, err := otlp.NewServer(
			otlp.ServerConfig{GRPCAddr: cfg.OTLPGRPCAddr, HTTPAddr: cfg.OTLPHTTPAddr},
			tlsCfg, otlp.NewTokenAuthenticator(cfg.OTLPTokens), sink, log)
		if err != nil {
			return fmt.Errorf("otlp receiver: %w", err)
		}
		g.Go(func() error { return otlpSrv.Run(gctx) })
	}

	// MCP server (S25): the Model Context Protocol HTTP transport — TLS + bearer-
	// authenticated, tenant- + RBAC-scoped read tools. Off unless configured.
	if cfg.MCPEnabled() {
		tlsCfg, err := loadServerTLS(cfg.MCPTLSCertFile, cfg.MCPTLSKeyFile)
		if err != nil {
			return fmt.Errorf("mcp tls: %w", err)
		}
		mcpSrv := control.NewMCPServer(cfg, log, db.Pool(), pathStore, cfg.MCPRatePerMin, fairGate, srv.RemediationService())
		handler := mcpSrv.HTTPHandler(control.NewMCPAuthenticator(db.Pool()))
		g.Go(func() error { return serveMCPHTTP(gctx, cfg.MCPHTTPAddr, tlsCfg, handler, log) })
	}

	return g.Wait()
}

// loadServerTLS builds a server TLS config from a cert/key pair. crypto/tls is
// permitted by the FIPS import guard; TLS policy stays centralized.
func loadServerTLS(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

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
