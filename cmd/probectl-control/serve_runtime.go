// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/ctlplne/probectl/internal/a2a"
	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/carbon"
	"github.com/ctlplne/probectl/internal/cluster"
	"github.com/ctlplne/probectl/internal/cmdb"
	"github.com/ctlplne/probectl/internal/compliance"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/control"
	"github.com/ctlplne/probectl/internal/cost"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/device"
	"github.com/ctlplne/probectl/internal/endpoint"
	"github.com/ctlplne/probectl/internal/enroll"
	"github.com/ctlplne/probectl/internal/fairness"
	"github.com/ctlplne/probectl/internal/flow"
	"github.com/ctlplne/probectl/internal/incident"
	"github.com/ctlplne/probectl/internal/license"
	"github.com/ctlplne/probectl/internal/notify"
	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/opendata"
	"github.com/ctlplne/probectl/internal/outage"
	"github.com/ctlplne/probectl/internal/path"
	"github.com/ctlplne/probectl/internal/pipeline"
	"github.com/ctlplne/probectl/internal/rum"
	"github.com/ctlplne/probectl/internal/secrets"
	"github.com/ctlplne/probectl/internal/siem"
	"github.com/ctlplne/probectl/internal/slo"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/store/ebpfstore"
	"github.com/ctlplne/probectl/internal/store/endpointstore"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/store/otelstore"
	"github.com/ctlplne/probectl/internal/store/pathstore"
	"github.com/ctlplne/probectl/internal/store/tsdb"
	"github.com/ctlplne/probectl/internal/support"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/threat"
	"github.com/ctlplne/probectl/internal/topology"
)

type serveRuntime struct {
	cfg             *config.Config
	db              *store.DB
	log             *slog.Logger
	secretsResolver *secrets.Resolver

	resultBus        bus.Bus
	tsdbWriter       tsdb.Writer
	tenantTSDBWriter tsdb.Writer
	ingestWriter     tsdb.Writer
	pathStore        pathstore.Store
	pathCH           *pathstore.ClickHouse
	otelStore        otelstore.Store
	flowStore        flowstore.Store
	flowQualityStore flow.QualityStore
	ebpfStore        ebpfstore.Store
	endpointStore    endpointstore.Store
	objectStore      objectstore.Store
	writerFence      tenancy.WriterFence

	ctx  context.Context
	stop context.CancelFunc
	g    *errgroup.Group
	gctx context.Context

	flowEnricher pipeline.FlowEnricher
	ipEnricher   *opendata.Enricher
	a2aBroker    *a2a.Broker

	dispatcher    *notify.Dispatcher
	cmdbResolver  *cmdb.Resolver
	correlator    *incident.Correlator
	tenantBinding pipeline.TenantBinding
	topoStore     topology.Store
	neighborStore device.NeighborStore
	outcomeStore  device.CollectionOutcomeStore

	costEngine       *cost.Engine
	carbonEngine     *carbon.Engine
	sloEngine        *slo.Engine
	complianceEngine *compliance.Engine
	lic              *license.Manager

	outageRefresher *outage.Refresher
	outageEngine    *outage.Engine
	outageOn        bool
	outageFeedsOn   bool

	rumEngine *rum.Engine
	rumApps   map[string]control.RUMApp
	rumOn     bool

	tlsPostures   *threat.PostureStore
	endpointViews *endpoint.Repository
	latestResults *control.LatestResults
	hopGeo        *path.GeoTable
	enrollSvc     *enroll.Service

	srv             *control.Server
	fairGate        *fairness.Gate
	lifeEngine      *tenantlife.Engine
	resultSinks     []control.ResultSink
	resultViewSinks []control.ResultSink
	siemFwd         *siem.Forwarder
	iocStore        *opendata.IOCStore
	iocRefresher    *opendata.IntelRefresher
	threatIntelOn   bool
	alertingActive  bool
	nsTenants       map[string]string
	singletons      *cluster.Coordinator
}

func runServe(cfg *config.Config, db *store.DB, log *slog.Logger, st *serveStores, secretsResolver *secrets.Resolver) error {
	rt := newServeRuntime(cfg, db, log, st, secretsResolver)
	defer rt.stop()

	rt.configureFlowEnrichment()
	if err := rt.buildServeEngines(); err != nil {
		return err
	}
	rt.configureThreatIntel()
	if err := rt.buildAPIServer(); err != nil {
		return err
	}
	if err := rt.startLifecycleAndServe(); err != nil {
		return err
	}
	rt.startIngestConsumers()
	if err := rt.startSignalConsumers(); err != nil {
		return err
	}
	rt.g.Go(func() error { return rt.singletons.Run(rt.gctx) })
	if err := rt.startEdgeTransports(); err != nil {
		return err
	}
	return rt.g.Wait()
}

func newServeRuntime(cfg *config.Config, db *store.DB, log *slog.Logger, st *serveStores, secretsResolver *secrets.Resolver) *serveRuntime {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	g, gctx := errgroup.WithContext(ctx)
	writerFence := tenancy.NewPostgresWriterFence(db.Pool())
	flowStore := flowstore.WithTenantWriteFence(
		st.flowStore,
		writerFence,
	)
	endpointStore := endpointstore.WithTenantWriteFence(
		st.endpointStore,
		writerFence,
	)
	ebpfStore := ebpfstore.WithTenantWriteFence(
		st.ebpfStore,
		writerFence,
	)
	otelStore := otelstore.WithTenantWriteFence(
		st.otelStore,
		writerFence,
	)
	pathStore := pathstore.WithTenantWriteFence(
		st.pathStore,
		writerFence,
	)
	tenantTSDBWriter := tsdb.WithTenantWriteFence(
		st.tsdbWriter,
		writerFence,
	)
	ingestWriter := tsdb.WithTenantWriteFence(
		st.ingestWriter,
		writerFence,
	)
	return &serveRuntime{
		cfg: cfg, db: db, log: log, secretsResolver: secretsResolver,
		resultBus: st.resultBus, tsdbWriter: st.tsdbWriter,
		tenantTSDBWriter: tenantTSDBWriter, ingestWriter: ingestWriter,
		pathStore: pathStore, pathCH: st.pathCH, otelStore: otelStore,
		flowStore: flowStore, ebpfStore: ebpfStore, endpointStore: endpointStore, objectStore: st.objectStore,
		writerFence: writerFence,
		ctx:         ctx, stop: stop, g: g, gctx: gctx,
		a2aBroker: a2a.NewBroker(),
	}
}

func (rt *serveRuntime) configureFlowEnrichment() {
	en, ok := control.BuildEnrichment(rt.cfg, rt.log)
	if !ok {
		return
	}
	async := pipeline.NewAsyncEnricher(en, rt.log)
	rt.flowEnricher = async
	rt.ipEnricher = en
	rt.g.Go(func() error { return async.Run(rt.gctx) })
	rt.log.Info("open-data enrichment enabled", "mode", "async")
}

func (rt *serveRuntime) buildServeEngines() error {
	rt.dispatcher, _ = control.BuildDispatcher(rt.cfg, rt.db.Pool(), rt.log)
	rt.cmdbResolver = control.BuildCMDB(rt.cfg, rt.log)
	rt.tenantBinding = pipeline.NewRegistryBinding(rt.db.Pool())
	rt.neighborStore = store.NewDeviceNeighbors(rt.db.Pool())
	rt.outcomeStore = store.NewDeviceCollectionOutcomes(rt.db.Pool())
	rt.flowQualityStore = store.NewFlowQualityReceipts(rt.db.Pool())

	var corrOpts []incident.Option
	if rt.dispatcher != nil {
		corrOpts = append(corrOpts, incident.WithObserver(control.NotifyObserver(rt.dispatcher, rt.log)))
		rt.log.Info("on-call/itsm integration enabled", "connectors", len(rt.cfg.NotifyConnectors))
		rt.g.Go(func() error {
			rt.dispatcher.RunReconciler(rt.gctx, time.Minute)
			return nil
		})
	}
	rt.correlator = control.BuildCorrelator(rt.db.Pool(), rt.cfg.IncidentWindow, rt.log, corrOpts...)

	if rt.cfg.TopologyEngine == "memory" {
		rt.topoStore = topology.NewMemoryStore()
	} else {
		rt.topoStore = topology.NewIndexedStore()
	}
	rt.topoStore = topology.WithTenantWriteFence(rt.topoStore, rt.writerFence)
	rt.log.Info("topology graph enabled", "engine", rt.cfg.TopologyEngine, "ebpf_store", rt.cfg.EBPFStoreMode)

	var costOn, carbonOn, sloOn, complianceOn bool
	var err error
	rt.costEngine, costOn, err = control.BuildCost(rt.cfg, rt.log)
	if err != nil {
		return err
	}
	rt.carbonEngine, carbonOn, err = control.BuildCarbon(rt.cfg, rt.log)
	if err != nil {
		return err
	}
	rt.sloEngine, sloOn, err = control.BuildSLO(rt.cfg, rt.log)
	if err != nil {
		return err
	}
	rt.complianceEngine, complianceOn, err = control.BuildCompliance(rt.cfg, rt.log)
	if err != nil {
		return err
	}
	rt.lic, err = control.BuildLicense(rt.cfg, rt.log)
	if err != nil {
		return err
	}

	outageStore, outageRefresher, outageFeedsOn := control.BuildOutageFeeds(rt.cfg, rt.log)
	rt.outageRefresher, rt.outageFeedsOn = outageRefresher, outageFeedsOn
	rt.outageEngine, rt.outageOn = control.BuildOutage(rt.cfg, outageStore, rt.ipEnricher, rt.log)
	if rt.outageFeedsOn {
		rt.g.Go(func() error { return rt.outageRefresher.Run(rt.gctx) })
	}
	if rt.outageOn {
		rt.log.Info("outage view enabled", "feeds", rt.outageFeedsOn, "scope_resolution", rt.ipEnricher != nil)
	}

	rt.rumEngine, rt.rumApps, rt.rumOn, err = control.BuildRUM(rt.cfg, rt.log)
	if err != nil {
		return err
	}
	if rt.rumOn {
		rt.log.Info("rum convergence enabled", "apps", len(rt.rumApps))
	}

	rt.tlsPostures = threat.NewPostureStore(0)
	rt.endpointViews = endpoint.NewRepository(rt.endpointStore, endpoint.NewSnapshotStore(0))
	rt.latestResults = control.NewLatestResults(0)
	// Hop geolocation is exclusively operator-supplied (never fetched): a
	// malformed table fails closed to "no enrichment" with a loud log.
	if rt.cfg.HopGeoFile != "" {
		table, geoErr := path.LoadGeoTable(rt.cfg.HopGeoFile)
		if geoErr != nil {
			rt.log.Warn("hop geo table disabled", "file", rt.cfg.HopGeoFile, "error", geoErr)
		} else {
			rt.hopGeo = table
			rt.log.Info("hop geo table loaded", "file", rt.cfg.HopGeoFile)
		}
	}
	rt.alertingActive = false
	_ = costOn
	_ = carbonOn
	_ = sloOn
	_ = complianceOn
	return rt.loadEnrollment()
}

func (rt *serveRuntime) loadEnrollment() error {
	enrollSvc, enrollErr := enroll.Load(context.Background(), rt.db.Pool(), rt.log)
	switch {
	case enrollErr == nil:
		rt.enrollSvc = enrollSvc
		rt.log.Info("agent enrollment enabled (SVID issuance active)", "leaf_ttl", enroll.DefaultLeafTTL.String())
	case errors.Is(enrollErr, store.ErrAgentCANotInitialized):
		rt.log.Info("agent enrollment not configured (run: probectl-control agent-ca init)")
	default:
		return fmt.Errorf("load agent enrollment service: %w", enrollErr)
	}
	return nil
}

func (rt *serveRuntime) buildAPIServer() error {
	rt.srv = control.New(rt.cfg, rt.log, rt.db, rt.db.Pool(), rt.pathStore, nil).
		WithDispatcher(rt.dispatcher).
		WithFlowStore(rt.flowStore).
		WithFlowQualityReceipts(rt.flowQualityStore).
		WithOTelStore(rt.otelStore).
		WithTSDB(rt.tsdbWriter).
		WithTSDBIngest(rt.tenantTSDBWriter).
		WithCMDB(rt.cmdbResolver).
		WithTLSPosture(rt.tlsPostures).
		WithOpenDataStatus(rt.ipEnricher, rt.iocStore, rt.iocRefresher).
		WithEndpointViews(rt.endpointViews).
		WithLatestResults(rt.latestResults).
		WithHopGeo(rt.hopGeo).
		WithSecrets(rt.secretsResolver).
		WithTopology(rt.topoStore).
		WithDeviceNeighbors(rt.neighborStore).
		WithDeviceCollectionOutcomes(rt.outcomeStore).
		WithEBPFStore(rt.ebpfStore).
		WithCost(rt.costEngine).
		WithCarbon(rt.carbonEngine)
	if rt.sloEngine != nil {
		rt.srv.WithSLO(rt.sloEngine)
	}
	if ch, ok := otelstore.ClickHouseStore(rt.otelStore); ok {
		ch.WithMetrics(rt.srv.Metrics())
	}
	if rt.ipEnricher != nil {
		rt.ipEnricher.WithMetrics(rt.srv.Metrics())
	}
	if rt.enrollSvc != nil {
		rt.srv.SetEnrollService(rt.enrollSvc)
	}
	singletons, err := cluster.NewSingletonCoordinator(rt.db.Pool(), "control-background",
		rt.cfg.SingletonLeaseInterval, rt.log)
	if err != nil {
		return fmt.Errorf("cluster singleton coordinator: %w", err)
	}
	rt.singletons = singletons.WithMetrics(rt.srv.Metrics())
	if rt.complianceEngine != nil {
		rt.srv.WithCompliance(rt.complianceEngine)
	}
	if rt.outageOn {
		rt.srv.WithOutage(rt.outageEngine)
	}
	if rt.outageFeedsOn {
		rt.srv.WithOutageFeeds(rt.outageRefresher)
	}
	if rt.rumOn {
		rt.srv.WithRUM(rt.rumEngine, rt.rumApps, rt.publishRUMEvent, rt.cfg.RUMRatePerMin)
	}
	rt.srv.WithLicense(rt.lic)
	rt.configureFairness()
	rt.srv.WithA2ABroker(rt.a2aBroker)
	if err := rt.configureTestSync(); err != nil {
		return err
	}
	if err := rt.configureEvidenceSigning(); err != nil {
		return err
	}
	if hn, herr := os.Hostname(); herr == nil && hn != "" {
		control.SetInstanceGroupSuffix(hn)
	}
	registerLossGauges(rt.srv.Metrics(), rt.resultBus, rt.tsdbWriter)
	registerAgentRegistryGauges(rt.srv.Metrics(), rt.db.Pool())
	registerClickHouseBreakerGauges(rt.srv.Metrics(), rt.pathCH, rt.flowStore)
	rt.g.Go(func() error {
		fairness.RunMetrics(rt.gctx, rt.tsdbWriter, rt.fairGate, 30*time.Second, rt.log)
		return nil
	})
	supportStart := time.Now()
	rt.g.Go(func() error {
		support.RunSelfMetrics(rt.gctx, rt.tsdbWriter, supportStart, 30*time.Second, rt.log)
		return nil
	})
	return nil
}

func (rt *serveRuntime) startTopologyConsumer() {
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "topology-consumer", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return control.NewTopologyConsumer(rt.resultBus, rt.topoStore, rt.log).
				WithTenantBinding(rt.tenantBinding).
				WithNamespaceTenants(snap.tenants).
				WithEBPFStore(rt.ebpfStore).
				WithDeviceNeighborStore(rt.neighborStore).
				WithDeviceCollectionOutcomeStore(rt.outcomeStore).
				WithStrictTenantLanes(rt.cfg.IngestStrictTenantLanes).
				WithMetrics(rt.srv.Metrics()).
				Run(ctx)
		})
	})
}

func (rt *serveRuntime) publishRUMEvent(ctx context.Context, tenant string, payload []byte) error {
	t, rerr := tenancy.CurrentRouter().TargetsFor(ctx, tenant)
	if rerr != nil {
		return fmt.Errorf("isolation routing unavailable (fail closed): %w", rerr)
	}
	topic, terr := bus.TopicFor(t.BusNamespace, bus.RUMEventsTopic)
	if terr != nil {
		return terr
	}
	return rt.resultBus.Publish(ctx, topic, []byte(tenant), payload)
}

func (rt *serveRuntime) configureFairness() {
	rt.fairGate = newFairnessGate(rt.cfg, rt.db.Pool())
	rt.srv.WithFairness(rt.fairGate)
}

func (rt *serveRuntime) configureTestSync() error {
	if rt.cfg.TestSyncSigningKeyFile == "" {
		return nil
	}
	tsPriv, _, _, err := crypto.LoadOrGenerateEd25519KeyFile(rt.cfg.TestSyncSigningKeyFile)
	if err != nil {
		return fmt.Errorf("testsync signing key: %w", err)
	}
	rt.srv.WithTestSyncKey(tsPriv)
	rt.log.Info("central test distribution enabled (signed bundles)", "key_file", rt.cfg.TestSyncSigningKeyFile)
	return nil
}

func (rt *serveRuntime) configureEvidenceSigning() error {
	var privatePEM []byte
	var publicPEM []byte
	var generated bool
	var err error
	switch {
	case strings.TrimSpace(rt.cfg.EvidenceSigningKey) != "":
		privatePEM, err = base64.StdEncoding.DecodeString(strings.TrimSpace(rt.cfg.EvidenceSigningKey))
		if err != nil {
			return fmt.Errorf("evidence signing key is not valid base64: %w", err)
		}
		publicPEM, err = crypto.PublicPEMFromPrivate(privatePEM)
	case rt.cfg.EvidenceSigningKeyFile != "":
		privatePEM, publicPEM, generated, err = crypto.LoadOrGenerateEd25519KeyFile(rt.cfg.EvidenceSigningKeyFile)
	default:
		return nil
	}
	if err != nil {
		return fmt.Errorf("evidence signing key: %w", err)
	}
	rt.srv.WithEvidenceSigningKey(privatePEM)
	if generated {
		rt.log.Warn("generated incident-evidence signing key; back up and publish its public fingerprint",
			"key_file", rt.cfg.EvidenceSigningKeyFile)
	}
	rt.log.Info("offline-verifiable incident evidence export enabled",
		"public_key_fingerprint", fmt.Sprintf("sha256:%x", crypto.Hash(publicPEM)))
	return nil
}

func (rt *serveRuntime) startLifecycleAndServe() error {
	lifeEngine, worm, err := startHAAndTenantLifecycle(rt.gctx, rt.g, rt.cfg, rt.db, rt.log,
		rt.srv, rt.singletons, rt.tsdbWriter, rt.flowStore, rt.lifecyclePathStore(), rt.topoStore, rt.lifecycleOTLPStore(), rt.lifecycleEBPFStore(), rt.objectStore)
	if err != nil {
		return err
	}
	rt.lifeEngine = lifeEngine
	rt.lifeEngine.WithEndpointRetention(rt.endpointViews)
	rt.lifeEngine.WithEndpointEvents(rt.endpointStore)
	if err := attachEE(rt.gctx, rt.srv, rt.cfg, rt.log, rt.lic, rt.db.Pool(), rt.latestResults,
		rt.flowStore, rt.pathCH, rt.ebpfStore, rt.otelStore, rt.endpointStore, rt.lifeEngine,
		worm, rt.secretsResolver.ResolveBytes, rt.fairGate, rt.topoStore, rt.singletons); err != nil {
		return err
	}
	channelDeps, err := control.BuildAlertChannelDeps(rt.cfg, rt.secretsResolver.Resolve, rt.log)
	if err != nil {
		return err
	}
	rt.srv.WithAlertChannelDeps(channelDeps)
	if sup, ok := control.BuildAlertEvaluatorSupervisor(rt.db.Pool(), rt.tsdbWriter, channelDeps,
		rt.cfg.AlertEvalInterval, control.AlertSink(rt.correlator, rt.log), rt.log,
		func(tenant string, src control.AlertStateSource) { rt.srv.WithAlertState(tenant, src) },
		func(tenant string) { rt.srv.WithoutAlertState(tenant) }); ok {
		rt.alertingActive = true
		if err := rt.singletons.Register("alert-evaluator", func(ctx context.Context, _ cluster.LeaseToken) error {
			sup.Run(ctx)
			return nil
		}); err != nil {
			return err
		}
	} else {
		rt.log.Warn("ALERTING INACTIVE: no query backend wired in this profile — stored rules will NOT evaluate")
	}
	if reports, ok := control.BuildDashboardReportSupervisor(rt.db.Pool(), time.Minute, rt.log); ok {
		if err := rt.singletons.Register("dashboard-report-scheduler", func(ctx context.Context, _ cluster.LeaseToken) error {
			reports.Run(ctx)
			return nil
		}); err != nil {
			return err
		}
	}
	rt.srv.WithAlertingActive(rt.alertingActive)
	rt.g.Go(func() error { return rt.srv.Run(rt.gctx) })
	return nil
}

// lifecycleEBPFStore exposes the concrete backend only to lifecycle capability
// discovery. Ingest, API, and edition wiring continue to use rt.ebpfStore so
// every production Insert remains protected by the durable writer fence.
func (rt *serveRuntime) lifecycleEBPFStore() ebpfstore.Store {
	return ebpfstore.UnderlyingStore(rt.ebpfStore)
}

// lifecycleOTLPStore exposes the concrete backend only to lifecycle capability
// discovery. Ingest, API, and edition wiring continue to use rt.otelStore so
// every production span and log write remains protected by the writer fence.
func (rt *serveRuntime) lifecycleOTLPStore() otelstore.Store {
	return otelstore.UnderlyingStore(rt.otelStore)
}

// lifecyclePathStore exposes the concrete backend only to lifecycle capability
// discovery. API, MCP, and result ingestion retain rt.pathStore so every direct
// or batched backend write remains protected by the writer fence.
func (rt *serveRuntime) lifecyclePathStore() pathstore.Store {
	return pathstore.UnderlyingStore(rt.pathStore)
}

func (rt *serveRuntime) startIngestConsumers() {
	if snap, err := loadBusLaneSnapshot(rt.gctx); err == nil {
		rt.nsTenants = snap.tenants
		if len(snap.namespaces) > 0 {
			rt.log.Info("isolation: consuming namespaced result lanes", "namespaces", snap.namespaces)
		}
	} else {
		rt.log.Warn("isolation: bus namespaces unavailable; consuming shared lanes only", "error", err.Error())
	}
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "result-pipeline", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return buildResultPipelineConsumer(rt.cfg, rt.resultBus, rt.ingestWriter, rt.log,
				snap.namespaces, snap.tenants, rt.tenantBinding, rt.fairGate, rt.srv.Metrics()).Run(ctx)
		})
	})
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "flow-pipeline", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return pipeline.NewFlowConsumer(rt.resultBus, rt.flowStore, rt.flowEnricher, rt.log).
				WithTenantBinding(rt.tenantBinding).
				WithNamespaceTenants(snap.tenants).
				WithStrictTenantLanes(rt.cfg.IngestStrictTenantLanes).
				WithFairness(rt.fairGate).
				WithMetrics(rt.srv.Metrics()).
				Run(ctx)
		})
	})
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "flow-quality-pipeline", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return pipeline.NewFlowQualityConsumer(rt.resultBus, rt.flowQualityStore, rt.log).
				WithTenantBinding(rt.tenantBinding).
				WithNamespaceTenants(snap.tenants).
				WithStrictTenantLanes(rt.cfg.IngestStrictTenantLanes).
				WithMetrics(rt.srv.Metrics()).
				Run(ctx)
		})
	})
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "device-pipeline", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return pipeline.NewDeviceConsumer(rt.resultBus, rt.ingestWriter, rt.log).
				WithFairness(rt.fairGate).
				WithMetrics(rt.srv.Metrics()).
				WithTenantBinding(rt.tenantBinding).
				WithNamespaceTenants(snap.tenants).
				WithStrictTenantLanes(rt.cfg.IngestStrictTenantLanes).
				Run(ctx)
		})
	})
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "endpoint-view", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return control.NewEndpointViewConsumer(rt.resultBus, rt.endpointViews, rt.log).
				WithTenantBinding(rt.tenantBinding).
				WithStrictTenantLanes(rt.cfg.IngestStrictTenantLanes).
				WithNamespaceTenants(snap.tenants).
				Run(ctx)
		})
	})
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "endpoint-events", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return control.NewEndpointEventConsumer(rt.resultBus, rt.endpointViews, rt.log).
				WithTenantBinding(rt.tenantBinding).
				WithStrictTenantLanes(rt.cfg.IngestStrictTenantLanes).
				WithNamespaceTenants(snap.tenants).
				Run(ctx)
		})
	})
	rt.resultViewSinks = append(rt.resultViewSinks, control.ResultSink{
		Name: "result-view", Fn: control.NewResultViewConsumer(rt.resultBus, rt.latestResults, rt.log).SinkResult})
}

func (rt *serveRuntime) startSLOAndComplianceConsumers() {
	if rt.sloEngine != nil {
		rt.g.Go(func() error {
			return superviseBusLaneRestart(rt.gctx, "slo-consumer", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
				return control.NewSLOConsumer(rt.resultBus, rt.sloEngine, rt.correlator, rt.log).
					WithNamespaceTenants(snap.tenants).
					Run(ctx)
			})
		})
	}
	if rt.complianceEngine != nil {
		rt.g.Go(func() error {
			return superviseBusLaneRestart(rt.gctx, "compliance-consumer", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
				return control.NewComplianceConsumer(rt.resultBus, rt.complianceEngine, rt.correlator, rt.log).
					WithSIEM(rt.siemFwd).
					WithTenantBinding(rt.tenantBinding).
					WithNamespaceTenants(snap.tenants).
					Run(ctx)
			})
		})
	}
}

func (rt *serveRuntime) startCostCarbonConsumers() {
	if rt.costEngine != nil {
		rt.g.Go(func() error {
			return superviseBusLaneRestart(rt.gctx, "cost-consumer", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
				return control.NewCostConsumer(rt.resultBus, rt.costEngine, rt.correlator, rt.log).
					WithTenantBinding(rt.tenantBinding).
					WithNamespaceTenants(snap.tenants).
					Run(ctx)
			})
		})
	}
	if rt.carbonEngine != nil {
		rt.g.Go(func() error {
			return superviseBusLaneRestart(rt.gctx, "carbon-consumer", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
				return control.NewCarbonConsumer(rt.resultBus, rt.carbonEngine, rt.log).
					WithNamespaceTenants(snap.tenants).
					Run(ctx)
			})
		})
	}
}

func (rt *serveRuntime) startOutageRUMConsumers() {
	if rt.outageOn {
		oc := control.NewOutageConsumer(rt.resultBus, rt.outageEngine, rt.correlator, rt.log).
			WithNamespaceTenants(rt.nsTenants)
		rt.resultSinks = append(rt.resultSinks, control.ResultSink{Name: "outage-vantage", Fn: oc.SinkResult})
	}
	if rt.rumOn {
		rc := control.NewRUMConsumer(rt.resultBus, rt.rumEngine, rt.correlator, rt.log)
		rt.resultSinks = append(rt.resultSinks, control.ResultSink{Name: "rum-synthetic", Fn: rc.SinkResult})
		rt.g.Go(func() error {
			return superviseBusLaneRestart(rt.gctx, "rum-views", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
				return control.NewRUMConsumer(rt.resultBus, rt.rumEngine, rt.correlator, rt.log).
					WithNamespaceTenants(snap.tenants).
					RunViews(ctx)
			})
		})
	}
}

func (rt *serveRuntime) startBGPIncidentConsumer() {
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "bgp-incident-consumer", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return control.NewBGPIncidentConsumer(rt.resultBus, rt.correlator, rt.log).
				WithNamespaceTenants(snap.tenants).
				Run(ctx)
		})
	})
}

func (rt *serveRuntime) startSignalConsumers() error {
	if err := rt.startSIEM(); err != nil {
		return err
	}
	rt.startThreatIntel()
	rt.startTopologyConsumer()
	rt.startCostCarbonConsumers()
	rt.startOutageRUMConsumers()
	rt.startBGPIncidentConsumer()
	rt.startSLOAndComplianceConsumers()
	if err := rt.startNDR(); err != nil {
		return err
	}
	rt.startTLSPostureSinks()
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "result-fan", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return control.NewResultFan(rt.resultBus, rt.log, rt.resultSinks...).
				WithNamespaceTenants(snap.tenants).
				Run(ctx)
		})
	})
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "result-read-views", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return control.NewResultFan(rt.resultBus, rt.log, rt.resultViewSinks...).
				WithViewGroup("result-read-views").
				WithNamespaceTenants(snap.tenants).
				Run(ctx)
		})
	})
	return nil
}

func (rt *serveRuntime) startSIEM() error {
	var siemOn bool
	rt.siemFwd, siemOn = control.BuildSIEM(rt.cfg, rt.log)
	if !siemOn {
		return nil
	}
	rt.g.Go(func() error { return rt.siemFwd.Run(rt.gctx) })
	poller := control.NewSIEMAuditPoller(rt.db.Pool(), rt.siemFwd, rt.cfg.SIEMRedactKeys, rt.cfg.SIEMPollInterval, rt.log)
	if err := rt.singletons.Register("siem-audit-poller", func(ctx context.Context, _ cluster.LeaseToken) error {
		return poller.Run(ctx)
	}); err != nil {
		return err
	}
	rt.log.Info("siem export enabled", "preset", rt.cfg.SIEMPreset, "poll", rt.cfg.SIEMPollInterval)
	return nil
}

func (rt *serveRuntime) startThreatIntel() {
	if !rt.threatIntelOn {
		return
	}
	rt.g.Go(func() error { return rt.iocRefresher.Run(rt.gctx) })
	ioc := control.NewIOCConsumer(rt.resultBus, rt.correlator, rt.iocStore, rt.log).
		WithSIEM(rt.siemFwd)
	rt.resultSinks = append(rt.resultSinks, control.ResultSink{Name: "threat-intel-ip", Fn: ioc.SinkResult})
	rt.log.Info("threat-intel enrichment enabled", "refresh", rt.cfg.ThreatIntelRefresh)
}

func (rt *serveRuntime) configureThreatIntel() {
	rt.iocStore, rt.iocRefresher, rt.threatIntelOn = control.BuildThreatIntel(rt.cfg, rt.log)
}

func (rt *serveRuntime) startNDR() error {
	ndrEngine, ndrOn, err := control.BuildNDR(rt.cfg, intelSourceOrNil(rt.iocStore), rt.topoStore, rt.log)
	if err != nil {
		return err
	}
	if !ndrOn {
		return nil
	}
	ndrc := control.NewNDRConsumer(rt.resultBus, ndrEngine, rt.correlator, rt.log).
		WithTenantBinding(rt.tenantBinding).
		WithNamespaceTenants(rt.nsTenants).
		WithFairness(rt.fairGate).
		WithSIEM(rt.siemFwd)
	rt.resultSinks = append(rt.resultSinks, control.ResultSink{Name: "ndr-dns", Fn: ndrc.SinkResult})
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "ndr-flow-lanes", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return ndrc.WithNamespaceTenants(snap.tenants).RunFlowLanes(ctx)
		})
	})
	return nil
}

func (rt *serveRuntime) startTLSPostureSinks() {
	tlsAnalyzer := control.BuildTLSAnalyzerWithMetrics(rt.cfg, rt.srv.Metrics())
	if rt.iocStore != nil {
		tlsAnalyzer.WithIntel(rt.iocStore)
	}
	tlsc := control.NewTLSPostureConsumer(rt.resultBus, rt.correlator, tlsAnalyzer, rt.log).
		WithSIEM(rt.siemFwd)
	rt.resultSinks = append(rt.resultSinks, control.ResultSink{Name: "tls-posture", Fn: tlsc.SinkResult})
	tlsView := control.NewTLSPostureConsumer(rt.resultBus, nil, tlsAnalyzer, rt.log).
		WithPostureStore(rt.tlsPostures)
	rt.resultViewSinks = append(rt.resultViewSinks, control.ResultSink{Name: "tls-posture-view", Fn: tlsView.SinkPosture})
	ebpfTLSView := control.NewEBPFTLSPostureConsumer(rt.resultBus, rt.tlsPostures, tlsAnalyzer, rt.log).
		WithTenantBinding(rt.tenantBinding).
		WithNamespaceTenants(rt.nsTenants)
	rt.g.Go(func() error {
		return superviseBusLaneRestart(rt.gctx, "tls-posture-ebpf-lanes", rt.log, func(ctx context.Context, snap busLaneSnapshot) error {
			return ebpfTLSView.WithNamespaceTenants(snap.tenants).Run(ctx)
		})
	})
}

func (rt *serveRuntime) startEdgeTransports() error {
	if err := startAgentTransport(rt.gctx, rt.g, rt.cfg, rt.db, rt.resultBus, rt.a2aBroker, rt.srv, rt.enrollSvc, rt.writerFence, rt.log); err != nil {
		return err
	}
	if err := startOTLPSubsystems(rt.gctx, rt.g, rt.cfg, rt.db, rt.resultBus, rt.ingestWriter, rt.otelStore, rt.fairGate, rt.srv, rt.log); err != nil {
		return err
	}
	if !rt.cfg.MCPEnabled() {
		return nil
	}
	tlsCfg, err := crypto.ServerTLSConfig(rt.cfg.MCPTLSCertFile, rt.cfg.MCPTLSKeyFile)
	if err != nil {
		return fmt.Errorf("mcp tls: %w", err)
	}
	mcpSrv := control.NewMCPServerWithPolicyLoader(rt.cfg, rt.log, rt.db.Pool(), rt.pathStore, rt.cfg.MCPRatePerMin,
		rt.srv.AIEgressGate(), rt.fairGate, rt.srv.RemediationService(),
		rt.srv.MCPPolicyLoader(),
		control.AISources{Metrics: rt.tsdbWriter, Flow: rt.flowStore, Topology: rt.topoStore})
	handler := mcpSrv.HTTPHandler(control.NewMCPAuthenticator(rt.db.Pool()))
	rt.g.Go(func() error { return serveMCPHTTP(rt.gctx, rt.cfg.MCPHTTPAddr, tlsCfg, handler, rt.log) })
	return nil
}
