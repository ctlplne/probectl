// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

// Package cluster is the core multi-region / active-active HA layer (S-EE2,
// F33). The control plane is stateless (S1/S34), so "active-active" means
// every region runs interchangeable API + ingest replicas; the durable state
// is one PostgreSQL writer (the primary) with streaming replicas in the other
// regions. This package owns region identity, the writer/reader split, and —
// the safety core — SPLIT-BRAIN FENCING.
//
// The honest Postgres model: there is exactly ONE writable primary at a time.
// A region failover promotes a standby and re-points the writer endpoint
// (DNS / proxy / managed-DB failover). Two failure modes must never silently
// corrupt state:
//
//   - the writer endpoint points at a read-only STANDBY (a half-finished
//     failover) — caught by pg_is_in_recovery();
//   - the writer endpoint points at a STALE ex-primary that is still
//     primary-role but was fenced off by a promotion elsewhere (a partition) —
//     caught by a monotonic promotion EPOCH recorded in cluster_state, which
//     the replicas carry forward from the true primary.
//
// When the writer is not provably the current primary, the control plane fails
// WRITES closed (a retryable 503) rather than risk a split-brain write — while
// READS keep serving from the local replica and telemetry pipelines never
// break (the house doctrine: degrade to read-only, never lose data).
package cluster

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Role is a database node's role as observed from a connection to it.
type Role string

const (
	RoleWriter  Role = "writer"  // a live primary, current promotion epoch
	RoleReader  Role = "reader"  // a standby (in recovery) or a read replica
	RoleStale   Role = "stale"   // a primary on a SUPERSEDED epoch (fence it)
	RoleUnknown Role = "unknown" // unreachable / probe error
)

// ReplicationMode documents the Postgres replication trade-off; it sets the
// achievable RPO. It is descriptive (the operator configures Postgres) — the
// control plane behaves the same either way.
type ReplicationMode string

const (
	// ReplicationSync — synchronous commit to a standby: RPO 0 (no committed
	// data is lost on failover), at the cost of write latency.
	ReplicationSync ReplicationMode = "sync"
	// ReplicationAsync — asynchronous: RPO is roughly the replication lag at
	// the moment of failure.
	ReplicationAsync ReplicationMode = "async"
)

// Topology is this replica's view of the multi-region deployment. It is a
// deployment property (config), not tenant data.
type Topology struct {
	Region          string          `json:"region"`              // this replica's region
	Regions         []string        `json:"regions"`             // every region in the deployment
	Residency       string          `json:"residency,omitempty"` // default data-residency region (governance)
	ReplicationMode ReplicationMode `json:"replication_mode"`    // sync | async
	RPOSeconds      float64         `json:"rpo_seconds"`         // target (provisional; human sign-off)
	RTOSeconds      float64         `json:"rto_seconds"`         // target (provisional; human sign-off)
}

// Probe is one observation of a database node: is it in recovery (a standby),
// and what promotion epoch + writer-region does its cluster_state row carry.
// LagSeconds is the replica's replay lag (0 / unset on a primary).
type Probe struct {
	InRecovery   bool
	Epoch        int64   // cluster_state.writer_epoch (monotonic across promotions)
	WriterRegion string  // cluster_state.writer_region
	LagSeconds   float64 // replica replay lag, when observable
	Err          error
}

// Prober observes one database endpoint. PGProber implements it over a pool;
// tests use a fake.
type Prober interface {
	Probe(ctx context.Context) Probe
}

// NodeStatus is the resolved, surfaced state of one endpoint.
type NodeStatus struct {
	Role         Role    `json:"role"`
	Epoch        int64   `json:"epoch"`
	WriterRegion string  `json:"writer_region,omitempty"`
	InRecovery   bool    `json:"in_recovery"`
	LagSeconds   float64 `json:"lag_seconds,omitempty"`
	Error        string  `json:"error,omitempty"`
	CheckedAgo   string  `json:"checked_ago,omitempty"`
}

// Status is the full cluster view for health/status + metrics. No tenant data.
type Status struct {
	Topology     Topology    `json:"topology"`
	Writer       NodeStatus  `json:"writer"`
	Reader       *NodeStatus `json:"reader,omitempty"`
	WritesUsable bool        `json:"writes_usable"`
	WritesReason string      `json:"writes_reason,omitempty"`
	HighestEpoch int64       `json:"highest_epoch"`
	// PoolFenced (DPR-089): the writer pool opens read-only sessions because the
	// writer endpoint resolves to a stale ex-primary; background writers fail
	// closed like the API.
	PoolFenced bool `json:"pool_fenced,omitempty"`
}

// Manager tracks cluster state and answers the write-fencing question. It is
// safe for concurrent use; Refresh runs on a ticker, WriterUsable / Status are
// read on the hot path.
type Manager struct {
	topo   Topology
	writer Prober
	reader Prober // optional (a local read replica)
	now    func() time.Time

	fencer WriteFencer  // optional (DPR-089): the writer pool's connection-level fence
	log    *slog.Logger // optional: fence transitions
	// probeTimeout bounds every probe (DPR-095). A vanished primary leaves
	// pooled sessions hanging on dead TCP peers; without a deadline the probe
	// blocked until the kernel gave up (~2 minutes on the lab) and the fence
	// engaged only then. Bounded, a lost primary is detected within one cycle.
	probeTimeout time.Duration

	mu           sync.RWMutex
	writerState  NodeStatus
	readerState  *NodeStatus
	highestEpoch int64
	checkedAt    time.Time
	started      bool
	poolFenced   bool // the fencer's current state (stale writer endpoint)
}

// NewManager builds a Manager. writer is required (the primary endpoint);
// reader is the optional local replica endpoint (nil routes reads to writer).
func NewManager(topo Topology, writer, reader Prober) *Manager {
	if topo.ReplicationMode == "" {
		topo.ReplicationMode = ReplicationAsync
	}
	return &Manager{
		topo:         topo,
		writer:       writer,
		reader:       reader,
		now:          time.Now,
		probeTimeout: DefaultProbeTimeout,
		writerState:  NodeStatus{Role: RoleUnknown, Error: "initial cluster probe has not completed"},
	}
}

// DefaultProbeTimeout bounds one probe of one endpoint (DPR-095): the probe
// interval is 5s, so a hung probe must fail within it.
const DefaultProbeTimeout = 5 * time.Second

// WithProbeTimeout overrides the per-probe deadline; non-positive keeps the
// default.
func (m *Manager) WithProbeTimeout(d time.Duration) *Manager {
	if d > 0 {
		m.probeTimeout = d
	}
	return m
}

// WriteFencer is the connection-level side of the split-brain fence (DPR-089):
// the store's writer pool. While the writer endpoint resolves to a stale
// ex-primary, FenceWrites(true) turns every new database session read-only and
// recycles the existing ones, so the control plane's background writers
// (heartbeats, incident signals, alert state, once-only export gates, audit)
// fail closed exactly as they would on a standby — the API-layer 503 alone
// only covers requests. It reports whether the state changed.
type WriteFencer interface {
	FenceWrites(on bool) bool
}

// WriteFenceReporter is an optional WriteFencer capability: report what the
// pool is ACTUALLY doing. Without it the status carries the manager's last
// instruction, which is not the same thing — a fence applied or lifted by any
// other path would leave /readyz describing a pool state that no longer holds.
type WriteFenceReporter interface {
	WritesFenced() bool
}

// WithWriteFencer attaches the writer pool's fence; nil leaves the fence at
// the API layer only.
func (m *Manager) WithWriteFencer(f WriteFencer) *Manager {
	m.fencer = f
	return m
}

// WithLogger logs fence transitions.
func (m *Manager) WithLogger(log *slog.Logger) *Manager {
	m.log = log
	return m
}

// withNow injects a clock (tests).
func (m *Manager) withNow(now func() time.Time) *Manager {
	if now != nil {
		m.now = now
	}
	return m
}

// Refresh probes the endpoints once and recomputes the fencing state. The
// epoch high-water mark only ever advances (monotonic): once a promotion to a
// newer epoch is seen anywhere, a node on an older epoch is fenced as stale.
func (m *Manager) Refresh(ctx context.Context) {
	wp := m.probe(ctx, m.writer)
	var rp *Probe
	if m.reader != nil {
		p := m.probe(ctx, m.reader)
		rp = &p
	}

	m.mu.Lock()
	m.checkedAt = m.now()
	m.started = true

	// The replica follows the TRUE primary, so its epoch advances the
	// high-water mark even while the writer endpoint is briefly stale.
	if rp != nil && rp.Err == nil && rp.Epoch > m.highestEpoch {
		m.highestEpoch = rp.Epoch
	}
	if wp.Err == nil && wp.Epoch > m.highestEpoch {
		m.highestEpoch = wp.Epoch
	}

	m.writerState = m.classify(wp)
	if rp != nil {
		rs := m.classify(*rp)
		m.readerState = &rs
	}
	// DPR-089: a stale ex-primary is fenced at the connection level too, so
	// the control plane's own background writers fail closed like the API.
	stale := m.writerState.Role == RoleStale
	epoch, highest := m.writerState.Epoch, m.highestEpoch
	if m.fencer != nil {
		m.poolFenced = stale
	}
	m.mu.Unlock()
	if m.fencer == nil || !m.fencer.FenceWrites(stale) || m.log == nil {
		return
	}
	if stale {
		m.log.Warn("writer pool fenced read-only: the writer endpoint resolves to a stale ex-primary; background writes fail closed until it is rebuilt or the endpoint moves", "epoch", epoch, "highest_epoch", highest)
	} else {
		m.log.Info("writer pool fence released: the writer endpoint is the current primary again", "epoch", epoch)
	}
}

// probe runs one bounded observation (DPR-095): a probe that outlives the
// deadline is reported as unreachable instead of stalling the fence.
func (m *Manager) probe(ctx context.Context, p Prober) Probe {
	timeout := m.probeTimeout
	if timeout <= 0 {
		timeout = DefaultProbeTimeout
	}
	pctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	done := make(chan Probe, 1)
	go func() { done <- p.Probe(pctx) }()
	select {
	case r := <-done:
		return r
	case <-pctx.Done():
		return Probe{Err: fmt.Errorf("cluster: probe exceeded %s: %w", timeout, pctx.Err())}
	}
}

// roleUnder resolves a probe to a role under a given promotion high-water epoch.
// It is pure (no shared state) so the authoritative write-path re-check
// (WriterUsableNow) can classify a FRESH probe against a locally-computed
// high-water mark without holding the manager lock.
func roleUnder(p Probe, highestEpoch int64) Role {
	switch {
	case p.Err != nil:
		return RoleUnknown
	case p.InRecovery:
		return RoleReader
	case p.Epoch < highestEpoch:
		// A primary on a superseded epoch: a stale ex-primary that a promotion
		// elsewhere has fenced off. NEVER write to it.
		return RoleStale
	default:
		return RoleWriter
	}
}

// classify resolves a probe into the surfaced status under the current
// high-water epoch.
func (m *Manager) classify(p Probe) NodeStatus {
	ns := NodeStatus{Epoch: p.Epoch, WriterRegion: p.WriterRegion, InRecovery: p.InRecovery, LagSeconds: p.LagSeconds}
	if !m.checkedAt.IsZero() {
		ns.CheckedAgo = m.now().Sub(m.checkedAt).Round(time.Millisecond).String()
	}
	ns.Role = roleUnder(p, m.highestEpoch)
	if p.Err != nil {
		ns.Error = p.Err.Error()
	}
	return ns
}

// writerVerdict turns a classified writer role into the fence decision and a
// human-readable reason when writes are refused. One voice for the cached read
// path (writerUsableLocked) and the authoritative write-path re-check
// (WriterUsableNow).
func writerVerdict(role Role, epoch, highestEpoch int64, errMsg string) (bool, string) {
	switch role {
	case RoleWriter:
		return true, ""
	case RoleReader:
		return false, "writer endpoint points at a read-only standby (failover in progress)"
	case RoleStale:
		return false, fmt.Sprintf("writer endpoint points at a stale primary (epoch %d < current %d) — fenced to prevent split-brain", epoch, highestEpoch)
	default:
		return false, "writer endpoint unreachable: " + errMsg
	}
}

// WriterUsable reports whether the writer endpoint was, as of the last periodic
// probe, provably the current primary, and a human-readable reason when it is
// not. It is the cheap cached read used by /readyz, metrics, and background
// gates. Mutating API requests go through WriterUsableNow, which re-probes so
// the fence is authoritative at write time (RTO-19) rather than up to one probe
// interval stale.
func (m *Manager) WriterUsable() (bool, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.writerUsableLocked()
}

// WriterUsableNow is the AUTHORITATIVE write-path fence check (RTO-19;
// docs/guardrails.md G7-1 and the house doctrine: degrade to read-only, never
// lose data). WriterUsable only reports the verdict cached by the last periodic
// Refresh (every ~5s); in the window between probes a node that has just stopped
// being the primary — demoted to a standby, killed, or superseded by a
// promotion elsewhere — still reads as usable, so a config write to it would be
// acknowledged (201) and then lost once the promoted primary takes over. This
// re-probes the endpoints SYNCHRONOUSLY and classifies the writer against the
// freshest promotion high-water mark, so the VERY NEXT write after the switch is
// fenced (503) — zero acknowledged-and-lost writes — instead of waiting for the
// next probe tick. It never mutates cached state (the periodic Refresh still
// owns that), and any probe error fails closed. The happy path is a single
// bounded round-trip to the local writer (and read replica, when configured),
// which mutating API traffic — never telemetry ingest — can afford.
func (m *Manager) WriterUsableNow(ctx context.Context) (bool, string) {
	if m == nil {
		return false, "cluster manager not configured"
	}
	if m.writer == nil {
		// No writer endpoint to re-probe: fall back to the cached verdict rather
		// than claim an authority we do not have.
		return m.WriterUsable()
	}
	m.mu.RLock()
	started := m.started
	highest := m.highestEpoch
	reader := m.reader
	m.mu.RUnlock()
	if !started {
		// Startup is the riskiest moment for split-brain; until the first probe
		// has established a baseline, fail closed (matches WriterUsable).
		return false, "initial cluster probe has not completed"
	}
	// Re-probe synchronously. The replica follows the TRUE primary, so its epoch
	// can raise the high-water mark the moment a promotion lands — letting us
	// detect a stale ex-primary before the next periodic Refresh folds it in.
	wp := m.probe(ctx, m.writer)
	if reader != nil {
		if rp := m.probe(ctx, reader); rp.Err == nil && rp.Epoch > highest {
			highest = rp.Epoch
		}
	}
	if wp.Err == nil && wp.Epoch > highest {
		highest = wp.Epoch
	}
	errMsg := ""
	if wp.Err != nil {
		errMsg = wp.Err.Error()
	}
	return writerVerdict(roleUnder(wp, highest), wp.Epoch, highest, errMsg)
}

// poolFencedLocked prefers the pool's own answer over the manager's last
// instruction to it (DPR-089).
func (m *Manager) poolFencedLocked() bool {
	if r, ok := m.fencer.(WriteFenceReporter); ok {
		return r.WritesFenced()
	}
	return m.poolFenced
}

// Status returns the full cluster view for health/status + metrics.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	usable, reason := m.writerUsableLocked()
	st := Status{
		Topology:     m.topo,
		Writer:       m.writerState,
		WritesUsable: usable,
		WritesReason: reason,
		HighestEpoch: m.highestEpoch,
		PoolFenced:   m.poolFencedLocked(),
	}
	if m.readerState != nil {
		rs := *m.readerState
		st.Reader = &rs
	}
	return st
}

// writerUsableLocked is the cached WriterUsable verdict without re-locking
// (callers hold mu).
func (m *Manager) writerUsableLocked() (bool, string) {
	if !m.started {
		return false, "initial cluster probe has not completed"
	}
	return writerVerdict(m.writerState.Role, m.writerState.Epoch, m.highestEpoch, m.writerState.Error)
}

// Run refreshes on a ticker until ctx is canceled (call once at startup).
func (m *Manager) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	m.Refresh(ctx) // resolve initial state before the first tick
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Refresh(ctx)
		}
	}
}
