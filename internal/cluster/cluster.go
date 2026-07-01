// SPDX-License-Identifier: LicenseRef-probectl-TBD

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
}

// Manager tracks cluster state and answers the write-fencing question. It is
// safe for concurrent use; Refresh runs on a ticker, WriterUsable / Status are
// read on the hot path.
type Manager struct {
	topo   Topology
	writer Prober
	reader Prober // optional (a local read replica)
	now    func() time.Time

	mu           sync.RWMutex
	writerState  NodeStatus
	readerState  *NodeStatus
	highestEpoch int64
	checkedAt    time.Time
	started      bool
}

// NewManager builds a Manager. writer is required (the primary endpoint);
// reader is the optional local replica endpoint (nil routes reads to writer).
func NewManager(topo Topology, writer, reader Prober) *Manager {
	if topo.ReplicationMode == "" {
		topo.ReplicationMode = ReplicationAsync
	}
	return &Manager{
		topo:        topo,
		writer:      writer,
		reader:      reader,
		now:         time.Now,
		writerState: NodeStatus{Role: RoleUnknown, Error: "initial cluster probe has not completed"},
	}
}

// WithNow injects a clock (tests).
func (m *Manager) WithNow(now func() time.Time) *Manager {
	if now != nil {
		m.now = now
	}
	return m
}

// Topology returns the configured topology.
func (m *Manager) Topology() Topology { return m.topo }

// Refresh probes the endpoints once and recomputes the fencing state. The
// epoch high-water mark only ever advances (monotonic): once a promotion to a
// newer epoch is seen anywhere, a node on an older epoch is fenced as stale.
func (m *Manager) Refresh(ctx context.Context) {
	wp := m.writer.Probe(ctx)
	var rp *Probe
	if m.reader != nil {
		p := m.reader.Probe(ctx)
		rp = &p
	}

	m.mu.Lock()
	defer m.mu.Unlock()
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
}

// classify resolves a probe into a role under the current high-water epoch.
func (m *Manager) classify(p Probe) NodeStatus {
	ns := NodeStatus{Epoch: p.Epoch, WriterRegion: p.WriterRegion, InRecovery: p.InRecovery, LagSeconds: p.LagSeconds}
	if !m.checkedAt.IsZero() {
		ns.CheckedAgo = m.now().Sub(m.checkedAt).Round(time.Millisecond).String()
	}
	switch {
	case p.Err != nil:
		ns.Role = RoleUnknown
		ns.Error = p.Err.Error()
	case p.InRecovery:
		ns.Role = RoleReader
	case p.Epoch < m.highestEpoch:
		// A primary on a superseded epoch: a stale ex-primary that a promotion
		// elsewhere has fenced off. NEVER write to it.
		ns.Role = RoleStale
	default:
		ns.Role = RoleWriter
	}
	return ns
}

// WriterUsable reports whether the writer endpoint is provably the current
// primary, and a human-readable reason when it is not. Mutating API requests
// are fenced (503) when this is false (fail closed — split-brain safety).
func (m *Manager) WriterUsable() (bool, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.started {
		return false, "initial cluster probe has not completed"
	}
	switch m.writerState.Role {
	case RoleWriter:
		return true, ""
	case RoleReader:
		return false, "writer endpoint points at a read-only standby (failover in progress)"
	case RoleStale:
		return false, fmt.Sprintf("writer endpoint points at a stale primary (epoch %d < current %d) — fenced to prevent split-brain", m.writerState.Epoch, m.highestEpoch)
	default:
		return false, "writer endpoint unreachable: " + m.writerState.Error
	}
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
	}
	if m.readerState != nil {
		rs := *m.readerState
		st.Reader = &rs
	}
	return st
}

// writerUsableLocked is WriterUsable without re-locking (callers hold mu).
func (m *Manager) writerUsableLocked() (bool, string) {
	if !m.started {
		return false, "initial cluster probe has not completed"
	}
	switch m.writerState.Role {
	case RoleWriter:
		return true, ""
	case RoleReader:
		return false, "writer endpoint points at a read-only standby (failover in progress)"
	case RoleStale:
		return false, fmt.Sprintf("writer endpoint points at a stale primary (epoch %d < current %d) — fenced to prevent split-brain", m.writerState.Epoch, m.highestEpoch)
	default:
		return false, "writer endpoint unreachable: " + m.writerState.Error
	}
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
