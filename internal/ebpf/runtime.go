// SPDX-License-Identifier: LicenseRef-probectl-TBD

package ebpf

import (
	"context"
	"log/slog"
	"sync/atomic"
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
	// l7seen tracks last-activity per connID so idle entries are swept on flush
	// (FUZZ-001) — connID is the SSL* pointer with no socket-close signal yet,
	// so without a TTL sweep l7conns + l7man.conns grow without bound.
	l7seen     map[uint64]time.Time
	l7connsCap int
	l7connsTTL time.Duration
	l7Evicted  atomic.Uint64

	lastDropStats  DropStats
	lastFilteredV6 uint64

	// ready flips true once the flow source is streaming — the readiness
	// probe's signal (OPS-001). started records process liveness.
	ready   atomic.Bool
	started atomic.Bool
}

// Ready reports whether the agent's source is attached and streaming (the
// k8s readiness probe). Live reports process liveness (the liveness probe).
func (a *Agent) Ready() bool { return a.ready.Load() }

// Live reports that the agent process is up and running its loop.
func (a *Agent) Live() bool { return a.started.Load() }

// L7Evicted reports how many L7 connection identities the agent has evicted
// (cap or idle-TTL) — the FUZZ-001 observability signal that the bound is live.
func (a *Agent) L7Evicted() uint64 { return a.l7Evicted.Load() }

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
		"cap_bpf", caps.CapBPF, "cap_perfmon", caps.CapPerfmon, "compiled", caps.Compiled,
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
		// Recorded replay (CI/demos) — not live plaintext capture; exempt
		// from the U-003 consent gate.
		if l7src, err = NewFixtureL7Source(cfg.L7FixturePath); err != nil {
			return nil, err
		}
	} else if ok, reason := l7CaptureAuthorized(cfg); !ok {
		// U-003: live TLS-plaintext capture is OFF unless explicitly enabled
		// AND consented for this agent's tenant. Off is the default posture.
		log.Info("ebpf L7 TLS capture off", "reason", reason)
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

	emitter, eerr := NewNamespacedBusEmitter(b, cfg.TenantID, cfg.Bus.Namespace)
	if eerr != nil {
		return nil, eerr // RED-006: malformed silo namespace refuses start
	}
	// EBPF-001/SCALE-003/FUZZ-001: wire the bounded maps into the LIVE runtime.
	// The bounded service map and the L7 connection caps existed but nothing in
	// the production path enabled them — so the default agent now sets them.
	agg.ServiceMap().SetBounds(cfg.MaxServiceEdges, cfg.L7ConnIdleTTL)
	l7man := l7.NewManager()
	l7man.SetBounds(cfg.MaxL7Conns, cfg.L7ConnIdleTTL)
	return &Agent{
		cfg:        cfg,
		log:        log,
		source:     src,
		l7source:   l7src,
		enricher:   NewProcEnricher(cfg.ProcRoot),
		emitter:    emitter,
		agg:        agg,
		l7man:      l7man,
		l7conns:    map[uint64]l7conn{},
		l7seen:     map[uint64]time.Time{},
		l7connsCap: cfg.MaxL7Conns,
		l7connsTTL: cfg.L7ConnIdleTTL,
	}, nil
}

// newAgentWith is a test seam: build an Agent from explicit collaborators. It
// honors cfg's map bounds so tests exercise the SAME bounded path production
// uses (the bound is wired in, not bypassed).
func newAgentWith(cfg *Config, log *slog.Logger, src Source, enr Enricher, em Emitter) *Agent {
	agg := NewAggregator()
	agg.ServiceMap().SetBounds(cfg.MaxServiceEdges, cfg.L7ConnIdleTTL)
	l7man := l7.NewManager()
	l7man.SetBounds(cfg.MaxL7Conns, cfg.L7ConnIdleTTL)
	return &Agent{
		cfg: cfg, log: log, source: src, enricher: enr, emitter: em,
		agg: agg, l7man: l7man, l7conns: map[uint64]l7conn{},
		l7seen: map[uint64]time.Time{}, l7connsCap: cfg.MaxL7Conns, l7connsTTL: cfg.L7ConnIdleTTL,
	}
}

// Run reads flows until ctx is canceled or the source is exhausted, emitting a
// batch every FlushInterval and a final batch on shutdown.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("ebpf agent starting",
		"tenant", a.cfg.TenantID, "host", a.cfg.Host,
		"flush", a.cfg.FlushInterval.String(), "topic", bus.EBPFFlowsTopic,
		"l7", a.l7source != nil)

	a.started.Store(true)
	flows, err := a.source.Flows(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = a.source.Close() }()
	// Source attached and streaming: readiness is satisfied (OPS-001).
	a.ready.Store(true)
	defer a.ready.Store(false)

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
		// FUZZ-001: cap the per-connection identity map. connID has no
		// socket-close correlation yet, so a churn of distinct connections would
		// grow l7conns (and l7man) without bound. Evict the oldest-seen first.
		if _, known := a.l7conns[ev.ConnID]; !known && a.l7connsCap > 0 && len(a.l7conns) >= a.l7connsCap {
			a.evictOldestL7Conn()
		}
		a.l7conns[ev.ConnID] = l7conn{
			src:       ev.Source,
			dst:       ev.Destination,
			transport: orString(ev.Transport, TransportTCP),
			tenant:    orString(ev.TenantID, a.cfg.TenantID),
			encrypted: ev.Encrypted,
		}
	}
	a.l7seen[ev.ConnID] = a.l7now(ev)
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

// l7now returns the event's timestamp (falling back to wall-clock), used as the
// last-seen marker that drives the idle sweep (FUZZ-001).
func (a *Agent) l7now(ev L7Event) time.Time {
	if !ev.Data.Time.IsZero() {
		return ev.Data.Time
	}
	return time.Now()
}

// evictOldestL7Conn drops the least-recently-seen connection's identity AND its
// parser tracker (l7man.Close), keeping l7conns and l7man bounded together.
func (a *Agent) evictOldestL7Conn() {
	var oldestID uint64
	var oldest time.Time
	first := true
	for id := range a.l7conns {
		seen := a.l7seen[id]
		if first || seen.Before(oldest) {
			oldestID, oldest, first = id, seen, false
		}
	}
	if !first {
		delete(a.l7conns, oldestID)
		delete(a.l7seen, oldestID)
		a.l7man.Close(oldestID) // flush+drop the parser tracker too
		a.l7Evicted.Add(1)
	}
}

// pruneL7 abandons connections idle longer than l7connsTTL (FUZZ-001), closing
// their parser trackers — and prunes the service map on the same cadence. It is
// driven by the flush ticker so the live agent enforces the bound continuously.
func (a *Agent) pruneL7(now time.Time) {
	if a.l7connsTTL > 0 {
		cutoff := now.Add(-a.l7connsTTL)
		for id, seen := range a.l7seen {
			if seen.Before(cutoff) {
				delete(a.l7conns, id)
				delete(a.l7seen, id)
				a.l7man.Close(id)
				a.l7Evicted.Add(1)
			}
		}
	}
	// Prune the L7 manager's own trackers (covers ids that produced data but no
	// l7conns identity) and the service map's idle edges.
	a.l7man.Prune(now)
	a.agg.ServiceMap().Prune(now)
}

func (a *Agent) flush(ctx context.Context) {
	a.pruneL7(time.Now())
	countersChanged := a.syncDrops()
	countersChanged = a.syncFilteredNonIPv4() || countersChanged
	flows, edges := a.agg.Drain()
	l7calls := a.agg.DrainL7()
	if len(flows) == 0 && len(edges) == 0 && len(l7calls) == 0 {
		if countersChanged {
			a.logFlushStats("ebpf counters updated", 0, 0, 0)
		}
		return
	}
	if err := a.emitter.Emit(ctx, flows, edges, l7calls); err != nil {
		a.log.Error("ebpf emit failed", "error", err, "flows", len(flows), "edges", len(edges), "l7_calls", len(l7calls))
		return
	}
	a.logFlushStats("ebpf flows emitted", len(flows), len(edges), len(l7calls))
}

func (a *Agent) logFlushStats(msg string, flows, edges, l7calls int) {
	st := a.agg.Stats()
	a.log.Info(msg,
		"tenant_id", a.cfg.TenantID, "flows", flows, "edges", edges, "l7_calls", l7calls,
		"observed_total", st.Observed, "l7_total", st.L7Observed, "dropped_total", st.Dropped,
		"drop_decode_failures_total", st.DecodeFailures,
		"drop_l4_ring_buffer_full_total", st.L4RingBufferFull,
		"drop_l7_ring_buffer_full_total", st.L7RingBufferFull,
		"drop_l7_active_read_failures_total", st.L7ActiveReadFailures,
		"drop_other_total", st.Other,
		"l7_attach_failures", st.L7AttachFailures, "filtered_non_ipv4_total", st.FilteredNonIPv4)
}

// syncDrops folds cumulative L4 + L7 source drop stats into the aggregator so
// dropped_total reflects kernel backpressure and map-stash loss, not just
// userspace decode failures.
func (a *Agent) syncDrops() bool {
	cur := dropStatsFrom(a.source)
	if a.l7source != nil {
		cur = cur.Add(dropStatsFrom(a.l7source))
	}
	delta := cur.Delta(a.lastDropStats)
	if delta.Total() > 0 {
		a.agg.RecordDropStats(delta)
	}
	a.lastDropStats = cur
	return delta.Total() > 0
}

// syncFilteredNonIPv4 folds the live source's in-kernel non-IPv4 filter count
// into the aggregator (U-073) — measurable, not silent. Sources that don't
// expose it (the fixture) are skipped.
func (a *Agent) syncFilteredNonIPv4() bool {
	fs, ok := a.source.(interface{ FilteredNonIPv4() uint64 })
	if !ok {
		return false
	}
	cur := fs.FilteredNonIPv4()
	if cur > a.lastFilteredV6 {
		a.agg.RecordFilteredNonIPv4(cur - a.lastFilteredV6)
		a.lastFilteredV6 = cur
		return true
	}
	return false
}
