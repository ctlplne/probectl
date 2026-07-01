// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
	"github.com/imfeelingtheagi/probectl/internal/alert"
	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/carbon"
	"github.com/imfeelingtheagi/probectl/internal/cmdb"
	"github.com/imfeelingtheagi/probectl/internal/compliance"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/control"
	"github.com/imfeelingtheagi/probectl/internal/cost"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/endpoint"
	"github.com/imfeelingtheagi/probectl/internal/enroll"
	"github.com/imfeelingtheagi/probectl/internal/fairness"
	"github.com/imfeelingtheagi/probectl/internal/incident"
	"github.com/imfeelingtheagi/probectl/internal/license"
	"github.com/imfeelingtheagi/probectl/internal/notify"
	"github.com/imfeelingtheagi/probectl/internal/opendata"
	"github.com/imfeelingtheagi/probectl/internal/outage"
	"github.com/imfeelingtheagi/probectl/internal/pipeline"
	"github.com/imfeelingtheagi/probectl/internal/rum"
	"github.com/imfeelingtheagi/probectl/internal/secrets"
	"github.com/imfeelingtheagi/probectl/internal/siem"
	"github.com/imfeelingtheagi/probectl/internal/slo"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/store/ebpfstore"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/otelstore"
	"github.com/imfeelingtheagi/probectl/internal/store/pathstore"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/support"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
	"github.com/imfeelingtheagi/probectl/internal/threat"
	"github.com/imfeelingtheagi/probectl/internal/topology"
)

type serveRuntime struct {
	cfg             *config.Config
	db              *store.DB
	log             *slog.Logger
	secretsResolver *secrets.Resolver

	resultBus    bus.Bus
	tsdbWriter   tsdb.Writer
	ingestWriter tsdb.Writer
	pathStore    pathstore.Store
	pathCH       *pathstore.ClickHouse
	otelStore    otelstore.Store
	flowStore    flowstore.Store
	ebpfStore    ebpfstore.Store

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
	endpointViews *endpoint.SnapshotStore
	latestResults *control.LatestResults
	enrollSvc     *enroll.Service

	srv             *control.Server
	fairGate        *fairness.Gate
	lifeEngine      *tenantlife.Engine
	resultSinks     []control.ResultSink
	resultViewSinks []control.ResultSink
	siemFwd         *siem.Forwarder
	iocStore        *opendata.IOCStore
	alertingActive  bool
	nsTenants       map[string]string
}

func runServe(cfg *config.Config, db *store.DB, log *slog.Logger, st *serveStores, secretsResolver *secrets.Resolver) error {
	rt := newServeRuntime(cfg, db, log, st, secretsResolver)
	defer rt.stop()

	rt.configureFlowEnrichment()
	if err := rt.buildServeEngines(); err != nil {
		return err
	}
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
	if err := rt.startEdgeTransports(); err != nil {
		return err
	}
	return rt.g.Wait()
}

func newServeRuntime(cfg *config.Config, db *store.DB, log *slog.Logger, st *serveStores, secretsResolver *secrets.Resolver) *serveRuntime {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	g, gctx := errgroup.WithContext(ctx)
	return &serveRuntime{
		cfg: cfg, db: db, log: log, secretsResolver: secretsResolver,
		resultBus: st.resultBus, tsdbWriter: st.tsdbWriter, ingestWriter: st.ingestWriter,
		pathStore: st.pathStore, pathCH: st.pathCH, otelStore: st.otelStore,
		flowStore: st.flowStore, ebpfStore: st.ebpfStore,
		ctx: ctx, stop: stop, g: g, gctx: gctx,
		a2aBroker: a2a.NewBroker(),
	}
}

func (rt *serveRuntime) configureFlowEnrichment() {
	if !rt.cfg.FlowEnrichASN {
		return
	}
	en := opendata.NewEnricher(rt.log, opendata.WithCacheMaxEntries(rt.cfg.FlowEnrichCacheMax))
	en.Register(opendata.NewCymru(net.DefaultResolver))
	async := pipeline.NewAsyncEnricher(en, rt.log)
	rt.flowEnricher = async
	rt.ipEnricher = en
	rt.g.Go(func() error { return async.Run(rt.gctx) })
	rt.log.Info("flow ASN enrichment enabled", "source", "team-cymru", "mode", "async")
}

func (rt *serveRuntime) buildServeEngines() error {
	rt.dispatcher, _ = control.BuildDispatcher(rt.cfg, rt.db.Pool(), rt.log)
	rt.cmdbResolver = control.BuildCMDB(rt.cfg, rt.log)
	rt.tenantBinding = pipeline.NewRegistryBinding(rt.db.Pool())

	var corrOpts []incident.Option
	if rt.dispatcher != nil {
		corrOpts = append(corrOpts, incident.WithObserver(control.NotifyObserver(rt.dispatcher, rt.log)))
		rt.log.Info("on-call/itsm integration enabled", "connectors", len(rt.cfg.NotifyConnectors))
	}
	rt.correlator = control.BuildCorrelator(rt.db.Pool(), rt.cfg.IncidentWindow, rt.log, corrOpts...)

	if rt.cfg.TopologyEngine == "memory" {
		rt.topoStore = topology.NewMemoryStore()
	} else {
		rt.topoStore = topology.NewIndexedStore()
	}
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
	rt.endpointViews = endpoint.NewSnapshotStore(0)
	rt.latestResults = control.NewLatestResults(0)
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
		WithOTelStore(rt.otelStore).
		WithTSDB(rt.tsdbWriter).
		WithCMDB(rt.cmdbResolver).
		WithTLSPosture(rt.tlsPostures).
		WithEndpointViews(rt.endpointViews).
		WithLatestResults(rt.latestResults).
		WithSecrets(rt.secretsResolver).
		WithTopology(rt.topoStore).
		WithEBPFStore(rt.ebpfStore).
		WithCost(rt.costEngine).
		WithCarbon(rt.carbonEngine)
	if rt.sloEngine != nil {
		rt.srv.WithSLO(rt.sloEngine)
	}
	if ch, ok := rt.otelStore.(*otelstore.ClickHouse); ok {
		ch.WithMetrics(rt.srv.Metrics())
	}
	if rt.ipEnricher != nil {
		rt.ipEnricher.WithMetrics(rt.srv.Metrics())
	}
	if rt.enrollSvc != nil {
		rt.srv.SetEnrollService(rt.enrollSvc)
	}
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
		return superviseRestart(rt.gctx, "topology-consumer", rt.log, func(ctx context.Context) error {
			return control.NewTopologyConsumer(rt.resultBus, rt.topoStore, rt.log).
				WithTenantBinding(rt.tenantBinding).
				WithNamespaceTenants(rt.nsTenants).
				WithEBPFStore(rt.ebpfStore).
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
	var fairnessSource fairness.PolicySource
	if rt.db.Pool() != nil {
		fairnessSource = fairness.NewPGStore(rt.db.Pool())
	}
	rt.fairGate = fairness.NewGate(fairness.Policy{
		ResultsPerSec:       rt.cfg.FairnessResultsPerSec,
		FlowEventsPerSec:    rt.cfg.FairnessFlowEventsPerSec,
		IngestBytesPerSec:   rt.cfg.FairnessIngestBytesPerSec,
		DeviceMetricsPerSec: rt.cfg.FairnessDeviceMetricsPerSec,
		OTLPSeriesPerSec:    rt.cfg.FairnessOTLPSeriesPerSec,
		BurstSeconds:        rt.cfg.FairnessBurstSeconds,
		QueryConcurrency:    rt.cfg.FairnessQueryConcurrency,
		QueriesPerMin:       rt.cfg.FairnessQueriesPerMin,
	}, fairnessSource).WithIdleTTL(rt.cfg.FairnessTenantIdleTTL)
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

func (rt *serveRuntime) startLifecycleAndServe() error {
	var err error
	rt.lifeEngine, err = startHAAndTenantLifecycle(rt.gctx, rt.g, rt.cfg, rt.db, rt.log,
		rt.srv, rt.tsdbWriter, rt.flowStore, rt.pathStore, rt.topoStore, rt.otelStore, rt.ebpfStore)
	if err != nil {
		return err
	}
	if err := attachEE(rt.gctx, rt.srv, rt.cfg, rt.log, rt.lic, rt.db.Pool(), rt.latestResults,
		rt.flowStore, rt.pathCH, rt.ebpfStore, rt.otelStore, rt.lifeEngine,
		rt.secretsResolver.Resolve, rt.fairGate, rt.topoStore); err != nil {
		return err
	}
	if sup, ok := control.BuildAlertEvaluatorSupervisor(rt.db.Pool(), rt.tsdbWriter, alert.ChannelDeps{},
		rt.cfg.AlertEvalInterval, control.AlertSink(rt.correlator, rt.log), rt.log,
		func(tenant string, src control.AlertStateSource) { rt.srv.WithAlertState(tenant, src) },
		func(tenant string) { rt.srv.WithoutAlertState(tenant) }); ok {
		rt.alertingActive = true
		if err := sup.Sync(rt.gctx); err != nil {
			rt.log.Warn("alert tenant sync failed", "error", err.Error())
		}
		rt.g.Go(func() error { sup.Run(rt.gctx); return nil })
	} else {
		rt.log.Warn("ALERTING INACTIVE: no query backend wired in this profile — stored rules will NOT evaluate")
	}
	rt.srv.WithAlertingActive(rt.alertingActive)
	rt.g.Go(func() error { return rt.srv.Run(rt.gctx) })
	return nil
}

func (rt *serveRuntime) startIngestConsumers() {
	busNamespaces, nsErr := tenancy.CurrentRouter().BusNamespaces(rt.gctx)
	if nsErr != nil {
		rt.log.Warn("isolation: bus namespaces unavailable; consuming shared lanes only", "error", nsErr.Error())
	} else if len(busNamespaces) > 0 {
		rt.log.Info("isolation: consuming namespaced result lanes", "namespaces", busNamespaces)
	}
	nsTenants, ntErr := tenancy.CurrentRouter().BusNamespaceTenants(rt.gctx)
	if ntErr != nil {
		rt.log.Warn("isolation: namespace-tenant map unavailable", "error", ntErr.Error())
	}
	rt.nsTenants = nsTenants
	rt.g.Go(func() error {
		return superviseRestart(rt.gctx, "result-pipeline", rt.log, func(ctx context.Context) error {
			return buildResultPipelineConsumer(rt.cfg, rt.resultBus, rt.ingestWriter, rt.log,
				busNamespaces, nsTenants, rt.tenantBinding, rt.fairGate, rt.srv.Metrics()).Run(ctx)
		})
	})
	rt.g.Go(func() error {
		return superviseRestart(rt.gctx, "flow-pipeline", rt.log, func(ctx context.Context) error {
			return pipeline.NewFlowConsumer(rt.resultBus, rt.flowStore, rt.flowEnricher, rt.log).
				WithTenantBinding(rt.tenantBinding).
				WithNamespaceTenants(nsTenants).
				WithStrictTenantLanes(rt.cfg.IngestStrictTenantLanes).
				WithFairness(rt.fairGate).
				WithMetrics(rt.srv.Metrics()).
				Run(ctx)
		})
	})
	rt.g.Go(func() error {
		return superviseRestart(rt.gctx, "device-pipeline", rt.log, func(ctx context.Context) error {
			return pipeline.NewDeviceConsumer(rt.resultBus, rt.ingestWriter, rt.log).
				WithFairness(rt.fairGate).
				WithMetrics(rt.srv.Metrics()).
				WithTenantBinding(rt.tenantBinding).
				WithNamespaceTenants(nsTenants).
				WithStrictTenantLanes(rt.cfg.IngestStrictTenantLanes).
				Run(ctx)
		})
	})
	rt.g.Go(func() error {
		return superviseRestart(rt.gctx, "endpoint-view", rt.log, func(ctx context.Context) error {
			return control.NewEndpointViewConsumer(rt.resultBus, rt.endpointViews, rt.log).
				WithNamespaceTenants(nsTenants).
				Run(ctx)
		})
	})
	rt.resultViewSinks = append(rt.resultViewSinks, control.ResultSink{
		Name: "result-view", Fn: control.NewResultViewConsumer(rt.resultBus, rt.latestResults, rt.log).SinkResult})
}

func (rt *serveRuntime) startSLOAndComplianceConsumers(nsTenants map[string]string) {
	if rt.sloEngine != nil {
		rt.g.Go(func() error {
			return superviseRestart(rt.gctx, "slo-consumer", rt.log, func(ctx context.Context) error {
				return control.NewSLOConsumer(rt.resultBus, rt.sloEngine, rt.correlator, rt.log).
					WithNamespaceTenants(nsTenants).
					Run(ctx)
			})
		})
	}
	if rt.complianceEngine != nil {
		rt.g.Go(func() error {
			return superviseRestart(rt.gctx, "compliance-consumer", rt.log, func(ctx context.Context) error {
				return control.NewComplianceConsumer(rt.resultBus, rt.complianceEngine, rt.correlator, rt.log).
					WithSIEM(rt.siemFwd).
					WithTenantBinding(rt.tenantBinding).
					WithNamespaceTenants(nsTenants).
					Run(ctx)
			})
		})
	}
}

func (rt *serveRuntime) startCostCarbonConsumers() {
	if rt.costEngine != nil {
		rt.g.Go(func() error {
			return superviseRestart(rt.gctx, "cost-consumer", rt.log, func(ctx context.Context) error {
				return control.NewCostConsumer(rt.resultBus, rt.costEngine, rt.correlator, rt.log).
					WithTenantBinding(rt.tenantBinding).
					WithNamespaceTenants(rt.nsTenants).
					Run(ctx)
			})
		})
	}
	if rt.carbonEngine != nil {
		rt.g.Go(func() error {
			return superviseRestart(rt.gctx, "carbon-consumer", rt.log, func(ctx context.Context) error {
				return control.NewCarbonConsumer(rt.resultBus, rt.carbonEngine, rt.log).
					WithNamespaceTenants(rt.nsTenants).
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
		rc := control.NewRUMConsumer(rt.resultBus, rt.rumEngine, rt.correlator, rt.log).
			WithNamespaceTenants(rt.nsTenants)
		rt.resultSinks = append(rt.resultSinks, control.ResultSink{Name: "rum-synthetic", Fn: rc.SinkResult})
		rt.g.Go(func() error {
			return superviseRestart(rt.gctx, "rum-views", rt.log, func(ctx context.Context) error {
				return rc.RunViews(ctx)
			})
		})
	}
}

func (rt *serveRuntime) startBGPIncidentConsumer() {
	rt.g.Go(func() error {
		return superviseRestart(rt.gctx, "bgp-incident-consumer", rt.log, func(ctx context.Context) error {
			return control.NewBGPIncidentConsumer(rt.resultBus, rt.correlator, rt.log).
				WithNamespaceTenants(rt.nsTenants).
				Run(ctx)
		})
	})
}

func (rt *serveRuntime) startSignalConsumers() error {
	rt.startSIEM()
	rt.startThreatIntel()
	rt.startTopologyConsumer()
	rt.startCostCarbonConsumers()
	rt.startOutageRUMConsumers()
	rt.startBGPIncidentConsumer()
	rt.startSLOAndComplianceConsumers(rt.nsTenants)
	if err := rt.startNDR(); err != nil {
		return err
	}
	rt.startTLSPostureSinks()
	resultFan := control.NewResultFan(rt.resultBus, rt.log, rt.resultSinks...).
		WithNamespaceTenants(rt.nsTenants)
	rt.g.Go(func() error {
		return superviseRestart(rt.gctx, "result-fan", rt.log, func(ctx context.Context) error {
			return resultFan.Run(ctx)
		})
	})
	resultViewFan := control.NewResultFan(rt.resultBus, rt.log, rt.resultViewSinks...).
		WithViewGroup("result-read-views").
		WithNamespaceTenants(rt.nsTenants)
	rt.g.Go(func() error {
		return superviseRestart(rt.gctx, "result-read-views", rt.log, func(ctx context.Context) error {
			return resultViewFan.Run(ctx)
		})
	})
	return nil
}

func (rt *serveRuntime) startSIEM() {
	var siemOn bool
	rt.siemFwd, siemOn = control.BuildSIEM(rt.cfg, rt.log)
	if !siemOn {
		return
	}
	rt.g.Go(func() error { return rt.siemFwd.Run(rt.gctx) })
	rt.g.Go(func() error {
		return control.NewSIEMAuditPoller(rt.db.Pool(), rt.siemFwd, rt.cfg.SIEMRedactKeys, rt.cfg.SIEMPollInterval, rt.log).Run(rt.gctx)
	})
	rt.log.Info("siem export enabled", "preset", rt.cfg.SIEMPreset, "poll", rt.cfg.SIEMPollInterval)
}

func (rt *serveRuntime) startThreatIntel() {
	iocStore, iocRefresher, intelOn := control.BuildThreatIntel(rt.cfg, rt.log)
	rt.iocStore = iocStore
	if !intelOn {
		return
	}
	rt.g.Go(func() error { return iocRefresher.Run(rt.gctx) })
	ioc := control.NewIOCConsumer(rt.resultBus, rt.correlator, rt.iocStore, rt.log).
		WithSIEM(rt.siemFwd)
	rt.resultSinks = append(rt.resultSinks, control.ResultSink{Name: "threat-intel-ip", Fn: ioc.SinkResult})
	rt.log.Info("threat-intel enrichment enabled", "refresh", rt.cfg.ThreatIntelRefresh)
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
	rt.g.Go(func() error { return ndrc.RunFlowLanes(rt.gctx) })
	return nil
}

func (rt *serveRuntime) startTLSPostureSinks() {
	tlsAnalyzer := control.BuildTLSAnalyzer(rt.cfg)
	if rt.iocStore != nil {
		tlsAnalyzer.WithIntel(rt.iocStore)
	}
	tlsc := control.NewTLSPostureConsumer(rt.resultBus, rt.correlator, tlsAnalyzer, rt.log).
		WithSIEM(rt.siemFwd)
	rt.resultSinks = append(rt.resultSinks, control.ResultSink{Name: "tls-posture", Fn: tlsc.SinkResult})
	tlsView := control.NewTLSPostureConsumer(rt.resultBus, nil, tlsAnalyzer, rt.log).
		WithPostureStore(rt.tlsPostures)
	rt.resultViewSinks = append(rt.resultViewSinks, control.ResultSink{Name: "tls-posture-view", Fn: tlsView.SinkPosture})
}

func (rt *serveRuntime) startEdgeTransports() error {
	if err := startAgentTransport(rt.gctx, rt.g, rt.cfg, rt.db, rt.resultBus, rt.a2aBroker, rt.srv, rt.enrollSvc, rt.log); err != nil {
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
	mcpSrv := control.NewMCPServer(rt.cfg, rt.log, rt.db.Pool(), rt.pathStore, rt.cfg.MCPRatePerMin,
		rt.srv.AIEgressGate(), rt.fairGate, rt.srv.RemediationService(),
		control.AISources{Metrics: rt.tsdbWriter, Flow: rt.flowStore, Topology: rt.topoStore})
	handler := mcpSrv.HTTPHandler(control.NewMCPAuthenticator(rt.db.Pool()))
	rt.g.Go(func() error { return serveMCPHTTP(rt.gctx, rt.cfg.MCPHTTPAddr, tlsCfg, handler, rt.log) })
	return nil
}
