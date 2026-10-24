// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ebpf

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/ebpf/l7"
	ebpfv1 "github.com/ctlplne/probectl/internal/gen/probectl/ebpf/v1"
	"github.com/ctlplne/probectl/internal/l7redact"
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
	// l7srcMu guards l7source once Run may attach a deferred live source
	// (D-43 S1: a consented capture whose control plane was unreachable at
	// start attaches on the first policy check that reaches it).
	l7srcMu sync.RWMutex
	// l7mode is the redaction mode this agent applies to every L7 call it
	// emits (D-43): its local l7_capture_redaction, never looser than the
	// tenant's floor.
	l7mode string
	// policy is the mTLS channel to the control plane that delivers the
	// tenant's redaction floor and takes the capture posture (D-43); nil when
	// no control_plane.grpc_addr is configured.
	policy   L7PolicyClient
	l7mu     sync.Mutex
	l7state  postureState
	l7live   atomic.Bool
	l7closed atomic.Bool
	// floorFailures counts consecutive failed policy checks; stoppedFloor is
	// the floor that stopped capture (D-43 S2). Run goroutine only.
	floorFailures int
	stoppedFloor  string
	l7man         *l7.Manager
	// dnsKey keys the D-65 DNS tokens; random per process, never leaves it.
	dnsKey  []byte
	l7conns map[uint64]l7conn
	// l7seen tracks last-activity per connID so idle entries are swept on flush
	// (FUZZ-001) — connID is the SSL* pointer with no socket-close signal yet,
	// so without a TTL sweep l7conns + l7man.conns grow without bound.
	l7seen     map[uint64]time.Time
	l7connsCap int
	l7connsTTL time.Duration
	l7Evicted  atomic.Uint64

	// join pairs the two sockets of a host-local connection into one edge
	// (ING-24); held client-side flows are folded in on the flush tick.
	join *hostLocalJoin

	lastDropStats  DropStats
	lastFilteredV6 uint64

	// Publish verification (DPR-071): the bus accepts records asynchronously,
	// so after every emit the agent flushes (bounded) and reads the bus's
	// failure counters; a failed or unacknowledged flush is logged at ERROR,
	// counted, and turns readiness off until a later flush delivers cleanly.
	flusher        bus.Flusher
	failures       bus.PublishFailureReporter
	publishTimeout time.Duration
	lastFailed     uint64
	lastShed       uint64
	publishFailed  atomic.Uint64 // records the bus reported undelivered + unacknowledged flushes
	publishBatches atomic.Uint64 // flushes that were acknowledged clean
	publishDegrade atomic.Bool   // the most recent flush did not deliver

	// ready flips true once the flow source is streaming — the readiness
	// probe's signal (OPS-001). started records process liveness.
	ready   atomic.Bool
	started atomic.Bool
}

// Ready reports whether the agent's source is attached and streaming (the
// k8s readiness probe). Live reports process liveness (the liveness probe).
func (a *Agent) Ready() bool {
	if !a.ready.Load() {
		return false
	}
	if a.publishDegrade.Load() { // DPR-071: flows are not being delivered
		return false
	}
	if h, ok := a.currentL7().(l7ScopeHealthReporter); ok && h.L7ScopeSyncDegraded() {
		return false
	}
	return true
}

// Live reports that the agent process is up and running its loop.
func (a *Agent) Live() bool { return a.started.Load() }

// L7Evicted reports how many L7 connection identities the agent has evicted
// (cap or idle-TTL) — the FUZZ-001 observability signal that the bound is live.
func (a *Agent) L7Evicted() uint64 { return a.l7Evicted.Load() }

// PublishFailures reports how many records the bus reported undelivered (plus
// flushes that were never acknowledged) — the DPR-071 signal that "emitted"
// actually means "delivered". PublishDegraded is true while the most recent
// flush failed to deliver; Ready() follows it.
func (a *Agent) PublishFailures() uint64 { return a.publishFailed.Load() }

// PublishDegraded reports whether the latest flush failed to deliver.
func (a *Agent) PublishDegraded() bool { return a.publishDegrade.Load() }

// L7CaptureRequested reports whether the config asked for live TLS-plaintext
// capture (enabled + consented for this agent's tenant). Paired with
// L7CaptureActive on the metrics endpoint so an operator can alert on
// "requested but not capturing" — the state DPR-124/125/126 all land in, which
// until now showed up only as one WARN at startup (DPR-128).
func (a *Agent) L7CaptureRequested() bool {
	if a.cfg == nil {
		return false
	}
	ok, _ := l7CaptureAuthorized(a.cfg)
	return ok
}

// L7CaptureActive reports whether a live L7 source is attached and can deliver
// encrypted-traffic visibility. A recorded fixture replay is not live capture.
func (a *Agent) L7CaptureActive() bool { return a.l7live.Load() }

// L7CaptureChannelRefused reports whether consented live capture is refused
// because there is no control-plane channel, the control plane could not
// record the capture posture, or the channel's identity is not this agent's
// (D-43 S1/S3).
func (a *Agent) L7CaptureChannelRefused() bool {
	a.l7mu.Lock()
	defer a.l7mu.Unlock()
	return a.l7state.state == l7StateRefusedChannel
}

// L7CaptureRefusedByFloor reports whether consented capture is refused because
// the agent's local redaction is looser than its tenant's floor (D-43).
func (a *Agent) L7CaptureRefusedByFloor() bool {
	a.l7mu.Lock()
	defer a.l7mu.Unlock()
	return a.l7state.state == l7StateRefusedFloor
}

// L7AttachFailures counts TLS-uprobe attach failures (U-015).
func (a *Agent) L7AttachFailures() uint64 { return a.agg.Stats().L7AttachFailures }

// withPublishVerification wires the bus capabilities the agent uses to confirm
// delivery after each emit; a bus without them is treated as synchronous.
func (a *Agent) withPublishVerification(b bus.Bus, timeout time.Duration) *Agent {
	if f, ok := b.(bus.Flusher); ok {
		a.flusher = f
	}
	if r, ok := b.(bus.PublishFailureReporter); ok {
		a.failures = r
		a.lastFailed, a.lastShed, _ = r.PublishFailures()
	}
	a.publishTimeout = timeout
	return a
}

// publishVerifyTimeout bounds the post-emit flush: half the flush interval,
// capped at 5s, so a broker outage costs a bounded wait per flush and never
// stalls observation.
func publishVerifyTimeout(flushInterval time.Duration) time.Duration {
	t := flushInterval / 2
	if t > 5*time.Second || t <= 0 {
		t = 5 * time.Second
	}
	return t
}

// l7conn remembers a connection's client→server identity so a call (which may be
// completed by a response event) is attributed to the request-direction edge.
type l7conn struct {
	src, dst  Endpoint
	transport string
	tenant    string
	encrypted bool
	tls       TLSMetadata
}

// New builds an Agent from cfg. It logs the capability probe and selects the
// flow Source: a FixtureSource when fixture_path is set (the no-kernel path),
// otherwise the live eBPF source (linked only under -tags ebpf).
func New(cfg *Config, b bus.Bus, log *slog.Logger) (*Agent, error) {
	// Fail closed on a missing bus rather than deferring an unavoidable nil
	// dereference to the first non-empty flush (§6: never panic in a
	// production path). Emit's publish path assumes a real bus; a nil one is
	// a wiring error at construction, and a quiet kernel that never flushes
	// must not disguise it.
	if b == nil {
		return nil, fmt.Errorf("ebpf: refusing to start: a bus is required to publish flows")
	}
	caps := Probe()
	log.Info("ebpf capability probe",
		"mode", string(caps.Mode), "btf", caps.BTF, "ringbuf", caps.RingBuffer,
		"cap_bpf", caps.CapBPF, "cap_perfmon", caps.CapPerfmon, "tracefs", caps.TraceFS, "compiled", caps.Compiled,
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
	logListenerSeed(log, src)

	policy, err := dialL7Policy(cfg.ControlPlane)
	if err != nil {
		return nil, err // a half-working policy channel refuses start (fail closed)
	}
	if policy != nil {
		if ierr := checkChannelIdentity(cfg); ierr != nil {
			// D-43 S3: never use another agent's channel. Without it,
			// consented live capture is refused (the flow plane runs on).
			log.Error("ebpf L7 capture REFUSED: the control-plane channel's identity is not this agent's (D-43)", "error", ierr.Error())
			_ = policy.Close()
			policy = nil
		}
	}
	return newAgent(cfg, b, log, src, policy)
}

// newAgent finishes construction with the flow source and the policy channel
// (nil = none). It is the seam the D-43 regression tests drive with a fake
// control plane.
func newAgent(cfg *Config, b bus.Bus, log *slog.Logger, src Source, policy L7PolicyClient) (*Agent, error) {
	agg := NewAggregator()
	emitter, eerr := NewNamespacedBusEmitter(b, cfg.TenantID, cfg.Bus.Namespace)
	if eerr != nil {
		if policy != nil {
			_ = policy.Close()
		}
		return nil, eerr // RED-006: malformed silo namespace refuses start
	}
	emitter.WithMaxBatchBytes(cfg.MaxBatchBytes) // DPR-071: bounded records
	// EBPF-001/SCALE-003/FUZZ-001: wire the bounded maps into the LIVE runtime.
	// The bounded service map and the L7 connection caps existed but nothing in
	// the production path enabled them — so the default agent now sets them.
	agg.ServiceMap().SetBounds(cfg.MaxServiceEdges, cfg.L7ConnIdleTTL)
	l7man := l7.NewManager()
	l7man.SetBounds(cfg.MaxL7Conns, cfg.L7ConnIdleTTL)
	a := &Agent{
		cfg:        cfg,
		log:        log,
		source:     src,
		policy:     policy,
		enricher:   NewProcEnricher(cfg.ProcRoot),
		emitter:    emitter,
		agg:        agg,
		l7man:      l7man,
		l7conns:    map[uint64]l7conn{},
		l7seen:     map[uint64]time.Time{},
		l7connsCap: cfg.MaxL7Conns,
		l7connsTTL: cfg.L7ConnIdleTTL,
		join:       newHostLocalJoin(),
		dnsKey:     newDNSKey(),
	}
	floor, floorErr := fetchFloor(context.Background(), policy)
	l7src, l7st, err := a.setupL7(context.Background(), floor, floorErr)
	if err != nil {
		if policy != nil {
			_ = policy.Close()
		}
		return nil, err
	}
	a.l7source, a.l7mode = l7src, l7st.mode
	a.setL7State(l7st)
	return a.withPublishVerification(b, publishVerifyTimeout(cfg.FlushInterval)), nil
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
		l7mode: l7redact.Normalize(cfg.L7CaptureRedaction),
		agg:    agg, l7man: l7man, l7conns: map[uint64]l7conn{},
		l7seen: map[uint64]time.Time{}, l7connsCap: cfg.MaxL7Conns, l7connsTTL: cfg.L7ConnIdleTTL,
		join: newHostLocalJoin(), dnsKey: newDNSKey(),
	}
}

// currentL7 returns the attached L7 source (nil when none).
func (a *Agent) currentL7() L7Source {
	a.l7srcMu.RLock()
	defer a.l7srcMu.RUnlock()
	return a.l7source
}

// startLiveL7 builds the live TLS/plaintext capture source. It is reached only
// after all three consent statements and the redaction floor have passed; the
// D-43 regression test (a) replaces it to prove exactly that.
var startLiveL7 = newLiveL7Source

// setupL7 decides whether L7 capture starts, and under which redaction mode:
// the consent gate first (U-003: enable + exact-tenant consent + scope; the
// recorded fixture replay is exempt — it is not live capture), then the
// tenant's redaction floor (D-43 refinement 3), which applies to the fixture
// replay too. Consented LIVE capture additionally requires the control-plane
// channel, and starts only after the control plane has recorded the posture it
// is about to run under (D-43 S1): no capture runs that the tenant's audit chain
// does not show. A refusal is a posture, never an error: the flow plane runs on.
func (a *Agent) setupL7(ctx context.Context, floor string, floorErr error) (L7Source, postureState, error) {
	cfg := a.cfg
	if cfg.L7FixturePath == "" {
		if ok, reason := l7CaptureAuthorized(cfg); !ok {
			state := l7StateOff
			if cfg.L7CaptureEnabled || cfg.L7CaptureConsentTenant != "" || len(cfg.L7CaptureScope) > 0 {
				state = l7StateRefusedConsent
			}
			// U-003: live TLS-plaintext capture is OFF unless explicitly
			// enabled AND consented for this agent's tenant. Off is the
			// default posture.
			a.log.Info("ebpf L7 TLS capture off", "reason", reason)
			return nil, postureState{state: state, floor: floor}, nil
		}
		if a.policy == nil {
			a.log.Error("ebpf L7 capture REFUSED: consented live capture requires the control-plane channel (D-43) — set control_plane.grpc_addr, cert_file, key_file and ca_file so the tenant's redaction floor applies and the capture posture reaches the tenant's audit chain")
			return nil, postureState{state: l7StateRefusedChannel}, nil
		}
	}
	d := decideL7Floor(cfg.L7CaptureRedaction, floor, floorErr)
	if d.refuse != "" {
		a.log.Error("ebpf L7 capture REFUSED by the tenant's redaction floor", "reason", d.refuse,
			"local_redaction", l7redact.Normalize(cfg.L7CaptureRedaction), "floor", d.floor)
		return nil, postureState{state: l7StateRefusedFloor, floor: d.floor}, nil
	}
	if d.clamped {
		a.log.Warn("ebpf L7 capture: no redaction floor received from the control plane — applying metadata (D-43)",
			"local_redaction", l7redact.Normalize(cfg.L7CaptureRedaction), "applied", d.mode, "reason", errString(floorErr))
	}
	if cfg.L7FixturePath != "" {
		fixture, err := NewFixtureL7Source(cfg.L7FixturePath)
		if err != nil {
			return nil, postureState{}, err
		}
		fixture.applyBoundary(d.mode, captureHeaderPolicy(cfg))
		return fixture, postureState{state: l7StateReplaying, mode: d.mode, floor: d.floor}, nil
	}
	// D-43 S1: the control plane records the posture BEFORE anything is
	// captured. If it cannot, capture waits; the next policy check retries.
	intent := postureState{state: l7StateCapturing, mode: d.mode, floor: d.floor}
	if err := a.reportState(ctx, intent); err != nil {
		a.log.Error("ebpf L7 capture NOT started: the control plane did not record the capture posture (D-43) — retried on the next policy check",
			"error", err.Error())
		return nil, postureState{state: l7StateRefusedChannel, floor: d.floor}, nil
	}
	liveCfg := *cfg
	liveCfg.L7CaptureRedaction = d.mode
	live, err := startLiveL7(&liveCfg, a.log)
	if err != nil {
		// U-015: a missing TLS uprobe is an encrypted-traffic VISIBILITY GAP —
		// warn loudly and count it (l7_attach_failures in the agent's stats);
		// it must never pass as a silent no-op.
		a.log.Warn("ebpf L7 TLS capture NOT attached — encrypted-traffic (HTTPS/gRPC) visibility is OFF on this host",
			"reason", err.Error())
		a.agg.RecordL7AttachFailure()
		return nil, postureState{state: l7StateAttachFailed, mode: d.mode, floor: d.floor}, nil
	}
	return live, postureState{state: l7StateCapturing, mode: d.mode, floor: d.floor, active: true}, nil
}

// retryDeferredL7 attaches a consented live capture that was refused only
// because the control plane could not record its posture (D-43 S1). It returns
// the new event stream, or nil when capture still cannot start.
func (a *Agent) retryDeferredL7(ctx context.Context) <-chan L7Event {
	a.l7mu.Lock()
	waiting := a.l7state.state == l7StateRefusedChannel
	a.l7mu.Unlock()
	if !waiting || a.policy == nil || a.currentL7() != nil {
		return nil
	}
	floor, floorErr := fetchFloor(ctx, a.policy)
	src, st, err := a.setupL7(ctx, floor, floorErr)
	if err != nil || src == nil {
		if st.state != "" {
			a.setL7State(st)
		}
		return nil
	}
	events, err := src.L7Events(ctx)
	if err != nil {
		_ = src.Close()
		return nil
	}
	a.l7srcMu.Lock()
	a.l7source = src
	a.l7srcMu.Unlock()
	a.l7mode = st.mode
	a.setL7State(st)
	a.reportPosture(ctx)
	a.log.Info("ebpf L7 capture attached after the control plane recorded its posture (D-43)", "mode", st.mode)
	return events
}

// Run reads flows until ctx is canceled or the source is exhausted, emitting a
// batch every FlushInterval and a final batch on shutdown.
func (a *Agent) Run(ctx context.Context) error {
	// DPR-051: log the identity every record carries and the lane it really
	// publishes on (the namespace was validated when the emitter was built).
	topic, _ := bus.TopicFor(a.cfg.Bus.Namespace, bus.EBPFFlowsTopic)
	a.log.Info("ebpf agent starting",
		"tenant", a.cfg.TenantID, "agent_id", a.cfg.identity(), "host", a.cfg.Host,
		"flush", a.cfg.FlushInterval.String(), "topic", topic,
		"l7", a.currentL7() != nil)

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
	}
	defer a.closeL7()
	if a.policy != nil {
		defer func() { _ = a.policy.Close() }()
	}
	// D-43: report the capture posture at registration with the control
	// plane, then on every policy tick (which also re-reads the floor).
	a.reportPosture(ctx)
	policyTick, stopPolicy := a.policyTicker()
	defer stopPolicy()

	ticker := time.NewTicker(a.cfg.FlushInterval)
	defer ticker.Stop()

	for flows != nil || l7events != nil {
		select {
		case <-policyTick:
			if ev := a.retryDeferredL7(ctx); ev != nil {
				l7events = ev
				continue
			}
			if a.refreshL7Floor(ctx) {
				a.closeL7()
				l7events = nil
			}
		case <-ctx.Done():
			a.flushFinal(context.WithoutCancel(ctx)) // best-effort final flush
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
	a.flushFinal(context.WithoutCancel(ctx))
	return nil
}

// closeL7 closes the L7 source once (on shutdown, or when a tightened floor
// stops capture).
func (a *Agent) closeL7() {
	// The field is never reassigned after construction (the health probe
	// reads it from another goroutine); closed records that it was closed.
	if src := a.currentL7(); src != nil && a.l7closed.CompareAndSwap(false, true) {
		_ = src.Close()
	}
}

// policyTicker returns the policy-refresh channel (nil, never firing, when
// there is no control-plane channel) and its stop function.
func (a *Agent) policyTicker() (<-chan time.Time, func()) {
	if a.policy == nil {
		return nil, func() {}
	}
	every := a.cfg.ControlPlane.PolicyInterval
	if every <= 0 {
		every = defaultL7PolicyInterval
	}
	t := time.NewTicker(every)
	return t.C, t.Stop
}

// observe stamps identity, enriches, and folds the flow into the aggregator.
// The agent is bound to exactly one tenant (its enrolled deployment identity),
// so a source-asserted FOREIGN tenant — a bad fixture, a corrupt recording —
// is REFUSED, never forwarded and never silently rewritten: the flow is
// dropped with an error log (fail closed, docs/guardrails.md G7-1). The
// tenant-verifying pipeline consumer re-checks downstream regardless.
//
// The agent_id is likewise the running collector's own registered identity, not
// the source's: a source-provided agent_id (e.g. the id baked into a bundled
// fixture) is OVERWRITTEN, never kept. The control plane verifies the
// (tenant_id, agent_id) pair against the tenant's registry, and only the
// collector's own registered id is guaranteed to resolve there — keeping a
// stale/foreign baked id made the control plane reject the whole batch
// ("agent not found") unless an operator hand-inserted that fixed id. This
// matches observeL7, which has always stamped a.cfg.identity() unconditionally.
func (a *Agent) observe(f Flow) {
	if f.TenantID != "" && f.TenantID != a.cfg.TenantID {
		a.log.Error("REJECTED flow: source asserted a foreign tenant (agent is tenant-bound, fail closed)",
			"asserted_tenant", f.TenantID, "bound_tenant", a.cfg.TenantID)
		return
	}
	f.TenantID = a.cfg.TenantID
	f.AgentID = a.cfg.identity()
	if f.Host == "" {
		f.Host = a.cfg.Host
	}
	if f.Observed.IsZero() {
		f.Observed = time.Now()
	}
	a.enricher.Enrich(&f)
	// Every observation is published as a raw flow; the service map gets the
	// client -> server view, with a host-local connection's two sockets
	// joined into one edge (ING-24).
	a.agg.Record(f)
	if edge, ok := a.join.admit(f, time.Now(), a.agg.ObserveEdge); ok {
		a.agg.ObserveEdge(edge)
	}
}

// releaseHeldFlows folds the client-side flows whose join hold expired into
// the service map (all of them on the final flush).
func (a *Agent) releaseHeldFlows(now time.Time, final bool) {
	for _, f := range a.join.release(now, final) {
		a.agg.ObserveEdge(f)
	}
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
		// Same tenant-bound contract as observe(): a source-asserted foreign
		// tenant is refused, never adopted (fail closed).
		if ev.TenantID != "" && ev.TenantID != a.cfg.TenantID {
			a.log.Error("REJECTED L7 event: source asserted a foreign tenant (agent is tenant-bound, fail closed)",
				"asserted_tenant", ev.TenantID, "bound_tenant", a.cfg.TenantID)
			return
		}
		a.l7conns[ev.ConnID] = l7conn{
			src:       ev.Source,
			dst:       ev.Destination,
			transport: orString(ev.Transport, TransportTCP),
			tenant:    a.cfg.TenantID,
			encrypted: ev.Encrypted,
			tls:       ev.TLS,
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
		// D-43: the shared persistence rule runs here, before the call is
		// rolled up or published — nothing beyond the mode's fields leaves
		// the agent, and under length no call does.
		if !l7redact.Persists(a.l7mode) {
			continue
		}
		var dns *ebpfv1.DNSFeatures
		if c.Protocol == l7.ProtoDNS {
			dns = dnsFeatures(c.Resource, a.dnsKey) // D-65: from the raw name, in memory only
		}
		c = minimizeCall(c, a.l7mode, a.dnsOptions())
		a.agg.ObserveL7(L7Record{
			DNS:         dns,
			TenantID:    meta.tenant,
			AgentID:     a.cfg.identity(),
			Source:      meta.src,
			Destination: meta.dst,
			Transport:   meta.transport,
			Encrypted:   meta.encrypted,
			TLS:         meta.tls,
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
	a.flushWith(ctx, false)
}

// flushFinal is the shutdown flush: every held flow is folded in first.
func (a *Agent) flushFinal(ctx context.Context) {
	a.flushWith(ctx, true)
}

func (a *Agent) flushWith(ctx context.Context, final bool) {
	a.releaseHeldFlows(time.Now(), final)
	a.pruneL7(time.Now())
	countersChanged := a.syncDrops()
	countersChanged = a.syncFilteredNonIPv4() || countersChanged
	flows, edges := a.agg.Drain()
	l7calls := a.reminimize(a.agg.DrainL7())
	if len(flows) == 0 && len(edges) == 0 && len(l7calls) == 0 {
		if countersChanged {
			a.logFlushStats("ebpf counters updated", 0, 0, 0)
		}
		return
	}
	if err := a.emitter.Emit(ctx, flows, edges, l7calls); err != nil {
		a.publishFailed.Add(1)
		a.publishDegrade.Store(true)
		a.log.Error("ebpf emit failed", "error", err, "flows", len(flows), "edges", len(edges), "l7_calls", len(l7calls))
		return
	}
	if !a.verifyPublished(ctx, len(flows), len(edges), len(l7calls)) {
		return
	}
	a.logFlushStats("ebpf flows emitted", len(flows), len(edges), len(l7calls))
}

// verifyPublished turns "accepted by the bus" into "delivered" (DPR-071): it
// flushes the async producer within publishTimeout and reads the bus's failure
// counters. Anything undelivered is logged at ERROR with the bus's own reason
// (e.g. MESSAGE_TOO_LARGE), counted, and marks the agent not-ready; a clean
// flush clears the degraded state. A bus without the capabilities is
// synchronous and counts as delivered.
func (a *Agent) verifyPublished(ctx context.Context, flows, edges, l7calls int) bool {
	if a.flusher != nil {
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.publishTimeout)
		err := a.flusher.Flush(fctx)
		cancel()
		if err != nil {
			a.publishFailed.Add(1)
			a.publishDegrade.Store(true)
			a.log.Error("ebpf publish NOT acknowledged — flows were not delivered to the bus",
				"error", err, "timeout", a.publishTimeout.String(),
				"flows", flows, "edges", edges, "l7_calls", l7calls,
				"publish_failures_total", a.publishFailed.Load())
			return false
		}
	}
	if a.failures != nil {
		failed, shed, last := a.failures.PublishFailures()
		if failed > a.lastFailed || shed > a.lastShed {
			lost := (failed - a.lastFailed) + (shed - a.lastShed)
			a.lastFailed, a.lastShed = failed, shed
			a.publishFailed.Add(lost)
			a.publishDegrade.Store(true)
			a.log.Error("ebpf publish FAILED — the bus rejected flow records after accepting them",
				"records_lost", lost, "error", errString(last),
				"flows", flows, "edges", edges, "l7_calls", l7calls,
				"max_batch_bytes", a.cfg.MaxBatchBytes,
				"publish_failures_total", a.publishFailed.Load())
			return false
		}
	}
	a.publishBatches.Add(1)
	a.publishDegrade.Store(false)
	return true
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
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
		"l7_scope_sync_failures_total", st.L7ScopeSyncFailures,
		"drop_other_total", st.Other,
		"l7_evicted_total", a.L7Evicted(),
		"service_map_evicted_total", a.agg.ServiceMap().Evicted(),
		"l7_manager_evicted_total", a.l7man.Evicted(),
		"l7_attach_failures", st.L7AttachFailures, "filtered_non_ipv4_total", st.FilteredNonIPv4,
		"publish_batches_total", a.publishBatches.Load(), "publish_failures_total", a.publishFailed.Load(),
		"publish_degraded", a.publishDegrade.Load())
}

// syncDrops folds cumulative L4 + L7 source drop stats into the aggregator so
// dropped_total reflects kernel backpressure and map-stash loss, not just
// userspace decode failures.
func (a *Agent) syncDrops() bool {
	cur := dropStatsFrom(a.source)
	if src := a.currentL7(); src != nil {
		cur = cur.Add(dropStatsFrom(src))
	}
	delta := cur.Delta(a.lastDropStats)
	if delta.Total() > 0 {
		a.agg.RecordDropStats(delta)
	}
	a.lastDropStats = cur
	return delta.Total() > 0
}

// syncFilteredNonIPv4 folds the live source's in-kernel unsupported-family
// filter count into the aggregator. The method keeps the legacy metric name;
// IPv6 is captured now. Sources that don't expose it (the fixture) are skipped.
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

// logListenerSeed says plainly how listeners that predate the agent were
// seeded (ING-24): by the task_file iterator, or not at all and why — a
// server started before the agent is then attributed only at close.
func logListenerSeed(log *slog.Logger, src Source) {
	ls, ok := src.(interface{ ListenerSeedReport() ListenerSeed })
	if !ok {
		return
	}
	seed := ls.ListenerSeedReport()
	if seed.Attributed() {
		log.Info("ebpf pre-existing listeners seeded", listenerSeedLogAttrs(seed)...)
		return
	}
	log.Warn("ebpf pre-existing listeners NOT seeded: a server started before the agent is attributed only when its connections close", listenerSeedLogAttrs(seed)...)
}
