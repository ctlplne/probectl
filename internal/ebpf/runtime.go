package ebpf

import (
	"context"
	"log/slog"
	"time"

	"github.com/imfeelingtheagi/netctl/internal/bus"
)

// Agent is the eBPF host agent runtime: it reads flows from a Source, enriches
// them, folds them into a service map, and emits batches to the bus on a flush
// ticker. It is observe-only and tenant-bound (F50): every flow is stamped with
// the agent's tenant, and ring-buffer drops are surfaced, never silent.
type Agent struct {
	cfg      *Config
	log      *slog.Logger
	source   Source
	enricher Enricher
	emitter  Emitter
	agg      *Aggregator

	lastDrops uint64
}

// New builds an Agent from cfg. It logs the capability probe and selects the
// flow Source: a FixtureSource when fixture_path is set (the no-kernel path),
// otherwise the live eBPF source (linked only under -tags ebpf).
func New(cfg *Config, b bus.Bus, log *slog.Logger) (*Agent, error) {
	caps := Probe()
	log.Info("ebpf capability probe",
		"mode", string(caps.Mode), "btf", caps.BTF, "ringbuf", caps.RingBuffer,
		"cap_bpf", caps.CapBPF, "compiled", caps.Compiled,
		"kernel", caps.KernelVersion, "reason", caps.Reason)

	var (
		src Source
		err error
	)
	if cfg.FixturePath != "" {
		src, err = NewFixtureSource(cfg.FixturePath)
	} else {
		src, err = newLiveSource(cfg)
	}
	if err != nil {
		return nil, err
	}

	return &Agent{
		cfg:      cfg,
		log:      log,
		source:   src,
		enricher: NewProcEnricher(cfg.ProcRoot),
		emitter:  NewBusEmitter(b, cfg.TenantID),
		agg:      NewAggregator(),
	}, nil
}

// newAgentWith is a test seam: build an Agent from explicit collaborators.
func newAgentWith(cfg *Config, log *slog.Logger, src Source, enr Enricher, em Emitter) *Agent {
	return &Agent{cfg: cfg, log: log, source: src, enricher: enr, emitter: em, agg: NewAggregator()}
}

// Run reads flows until ctx is canceled or the source is exhausted, emitting a
// batch every FlushInterval and a final batch on shutdown.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("ebpf agent starting",
		"tenant", a.cfg.TenantID, "host", a.cfg.Host,
		"flush", a.cfg.FlushInterval.String(), "topic", bus.EBPFFlowsTopic)

	flows, err := a.source.Flows(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = a.source.Close() }()

	ticker := time.NewTicker(a.cfg.FlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.flush(context.WithoutCancel(ctx)) // best-effort final flush
			return nil
		case f, ok := <-flows:
			if !ok {
				a.flush(ctx)
				return nil
			}
			a.observe(f)
		case <-ticker.C:
			a.flush(ctx)
		}
	}
}

// observe stamps identity (defense-in-depth — the source may omit it), enriches,
// and folds the flow into the aggregator.
func (a *Agent) observe(f Flow) {
	if f.TenantID == "" {
		f.TenantID = a.cfg.TenantID
	}
	if f.AgentID == "" {
		f.AgentID = a.cfg.Host
	}
	if f.Host == "" {
		f.Host = a.cfg.Host
	}
	if f.Observed.IsZero() {
		f.Observed = time.Now()
	}
	a.enricher.Enrich(&f)
	a.agg.Observe(f)
}

func (a *Agent) flush(ctx context.Context) {
	a.syncDrops()
	flows, edges := a.agg.Drain()
	if len(flows) == 0 && len(edges) == 0 {
		return
	}
	if err := a.emitter.Emit(ctx, flows, edges); err != nil {
		a.log.Error("ebpf emit failed", "error", err, "flows", len(flows), "edges", len(edges))
		return
	}
	st := a.agg.Stats()
	a.log.Info("ebpf flows emitted",
		"tenant_id", a.cfg.TenantID, "flows", len(flows), "edges", len(edges),
		"observed_total", st.Observed, "dropped_total", st.Dropped)
}

// syncDrops folds the source's cumulative drop count into the aggregator so the
// dropped_total metric reflects ring-buffer backpressure.
func (a *Agent) syncDrops() {
	cur := a.source.Drops()
	if cur > a.lastDrops {
		a.agg.RecordDrops(cur - a.lastDrops)
		a.lastDrops = cur
	}
}
