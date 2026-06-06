package ebpf

import (
	"context"
	"log/slog"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/bus"
	"github.com/imfeelingtheagi/probectl/internal/ebpf/l7"
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

	l7source L7Source
	l7man    *l7.Manager
	l7conns  map[uint64]l7conn

	lastDrops uint64
}

// l7conn remembers a connection's client→server identity so a call (which may be
// completed by a response event) is attributed to the request-direction edge.
type l7conn struct {
	src, dst  Endpoint
	transport string
	tenant    string
	encrypted bool
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

	agg := NewAggregator()
	var l7src L7Source
	if cfg.L7FixturePath != "" {
		if l7src, err = NewFixtureL7Source(cfg.L7FixturePath); err != nil {
			return nil, err
		}
	} else if live, lerr := newLiveL7Source(cfg); lerr == nil {
		l7src = live
	} else {
		// U-015: a missing TLS uprobe is an encrypted-traffic VISIBILITY GAP —
		// warn loudly and count it (l7_attach_failures in the agent's stats);
		// it must never pass as a silent no-op.
		log.Warn("ebpf L7 TLS capture NOT attached — encrypted-traffic (HTTPS/gRPC) visibility is OFF on this host",
			"reason", lerr.Error())
		agg.RecordL7AttachFailure()
	}

	return &Agent{
		cfg:      cfg,
		log:      log,
		source:   src,
		l7source: l7src,
		enricher: NewProcEnricher(cfg.ProcRoot),
		emitter:  NewBusEmitter(b, cfg.TenantID),
		agg:      agg,
		l7man:    l7.NewManager(),
		l7conns:  map[uint64]l7conn{},
	}, nil
}

// newAgentWith is a test seam: build an Agent from explicit collaborators.
func newAgentWith(cfg *Config, log *slog.Logger, src Source, enr Enricher, em Emitter) *Agent {
	return &Agent{
		cfg: cfg, log: log, source: src, enricher: enr, emitter: em,
		agg: NewAggregator(), l7man: l7.NewManager(), l7conns: map[uint64]l7conn{},
	}
}

// Run reads flows until ctx is canceled or the source is exhausted, emitting a
// batch every FlushInterval and a final batch on shutdown.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("ebpf agent starting",
		"tenant", a.cfg.TenantID, "host", a.cfg.Host,
		"flush", a.cfg.FlushInterval.String(), "topic", bus.EBPFFlowsTopic,
		"l7", a.l7source != nil)

	flows, err := a.source.Flows(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = a.source.Close() }()

	var l7events <-chan L7Event
	if a.l7source != nil {
		if l7events, err = a.l7source.L7Events(ctx); err != nil {
			return err
		}
		defer func() { _ = a.l7source.Close() }()
	}

	ticker := time.NewTicker(a.cfg.FlushInterval)
	defer ticker.Stop()

	for flows != nil || l7events != nil {
		select {
		case <-ctx.Done():
			a.flush(context.WithoutCancel(ctx)) // best-effort final flush
			return nil
		case f, ok := <-flows:
			if !ok {
				flows = nil
				continue
			}
			a.observe(f)
		case ev, ok := <-l7events:
			if !ok {
				l7events = nil
				continue
			}
			a.observeL7(ev)
		case <-ticker.C:
			a.flush(ctx)
		}
	}
	a.flush(context.WithoutCancel(ctx))
	return nil
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

// observeL7 routes a captured plaintext chunk to its connection's parser and
// rolls any completed calls onto the request-direction edge.
func (a *Agent) observeL7(ev L7Event) {
	if ev.Data.Kind == l7.Request {
		a.l7conns[ev.ConnID] = l7conn{
			src:       ev.Source,
			dst:       ev.Destination,
			transport: orString(ev.Transport, TransportTCP),
			tenant:    orString(ev.TenantID, a.cfg.TenantID),
			encrypted: ev.Encrypted,
		}
	}
	meta, ok := a.l7conns[ev.ConnID]
	if !ok {
		return // a response with no prior request — can't attribute; drop
	}
	port := meta.dst.Port
	if port == 0 {
		port = ev.Destination.Port
	}
	for _, c := range a.l7man.OnData(ev.ConnID, port, ev.Data) {
		a.agg.ObserveL7(L7Record{
			TenantID:    meta.tenant,
			AgentID:     a.cfg.Host,
			Source:      meta.src,
			Destination: meta.dst,
			Transport:   meta.transport,
			Encrypted:   meta.encrypted,
			Call:        c,
		})
	}
}

func (a *Agent) flush(ctx context.Context) {
	a.syncDrops()
	flows, edges := a.agg.Drain()
	l7calls := a.agg.DrainL7()
	if len(flows) == 0 && len(edges) == 0 && len(l7calls) == 0 {
		return
	}
	if err := a.emitter.Emit(ctx, flows, edges, l7calls); err != nil {
		a.log.Error("ebpf emit failed", "error", err, "flows", len(flows), "edges", len(edges), "l7_calls", len(l7calls))
		return
	}
	st := a.agg.Stats()
	a.log.Info("ebpf flows emitted",
		"tenant_id", a.cfg.TenantID, "flows", len(flows), "edges", len(edges), "l7_calls", len(l7calls),
		"observed_total", st.Observed, "l7_total", st.L7Observed, "dropped_total", st.Dropped,
		"l7_attach_failures", st.L7AttachFailures)
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
