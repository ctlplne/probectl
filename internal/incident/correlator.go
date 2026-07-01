// SPDX-License-Identifier: LicenseRef-probectl-TBD

package incident

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// DefaultWindow is the correlation time window when none is configured.
const DefaultWindow = 10 * time.Minute

// MaxFutureSkew is how far ahead of ingest time a signal's OccurredAt may be
// before it is treated as clock skew and clamped (CORRECT-009). A signal's event
// time is sourced from independent planes (NDR, BGP, TLS, IOC) whose clocks may
// drift; a far-future OccurredAt would extend an incident's LastSeenAt — and so
// its correlation window — unboundedly, keeping the incident "live" forever and
// swallowing unrelated later signals. Small benign skew passes through; gross
// future-dating is clamped to ingest time.
const MaxFutureSkew = 5 * time.Minute

// Store persists incidents and their signals. Methods are tenant-parameterized so
// a backing store can scope each operation (RLS); correlation never crosses
// tenants. AppendSignal must atomically insert the signal and update the
// incident's last-seen, severity (max), and signal count, returning the refreshed
// incident.
type Store interface {
	OpenIncidents(ctx context.Context, tenant string) ([]*Incident, error)
	Create(ctx context.Context, inc *Incident) (*Incident, error)
	AppendSignal(ctx context.Context, tenant, incidentID string, sig Signal) (*Incident, error)
}

// TransactionalStore can serialize the read-correlate-create sequence in the
// durable backing store. HA control-plane replicas do not share Correlator's
// in-process mutex, so Postgres-backed stores use this seam to hold a tenant-keyed
// transaction advisory lock across OpenIncidents/Create/AppendSignal.
type TransactionalStore interface {
	Store
	WithTenantCorrelationLock(ctx context.Context, tenant string, fn func(context.Context, Store) error) error
}

// Observer is notified of an incident lifecycle transition during Ingest: opened
// is true when the signal opened a NEW incident, false when it was correlated
// into an existing one. It runs after the store commits and after the tenant
// correlation lock is released, so it sees a persisted incident without putting
// connector backpressure on the correlation critical section. A nil observer is
// a no-op.
type Observer func(ctx context.Context, inc *Incident, opened bool)

// Option configures a Correlator.
type Option func(*Correlator)

// WithObserver registers a lifecycle observer (S33: page on-call + open a ticket
// when an incident opens).
func WithObserver(o Observer) Option {
	return func(c *Correlator) { c.observer = o }
}

// Correlator groups incoming signals into incidents.
type Correlator struct {
	store    Store
	window   time.Duration
	log      *slog.Logger
	observer Observer
	now      func() time.Time // injectable clock (CORRECT-009 skew clamp; tests)

	// tenantLocks serializes the read-then-create sequence PER TENANT inside
	// one process (CORRECT-013). Durable stores can add cross-replica
	// serialization by implementing TransactionalStore; the local lock still
	// prevents needless same-process contention while tenant-keyed DB locks
	// protect HA replicas.
	tenantLocks sync.Map // tenant id -> *sync.Mutex
}

// tenantLock returns the per-tenant mutex, creating it on first use.
func (c *Correlator) tenantLock(tenant string) *sync.Mutex {
	m, _ := c.tenantLocks.LoadOrStore(tenant, &sync.Mutex{})
	return m.(*sync.Mutex)
}

// NewCorrelator builds a correlator over store with the given time window.
func NewCorrelator(store Store, window time.Duration, log *slog.Logger, opts ...Option) *Correlator {
	if window <= 0 {
		window = DefaultWindow
	}
	if log == nil {
		log = slog.Default()
	}
	c := &Correlator{store: store, window: window, log: log, now: time.Now}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// withClock overrides the clock (test-only; CORRECT-009 skew clamp).
func (c *Correlator) withClock(now func() time.Time) *Correlator {
	if now != nil {
		c.now = now
	}
	return c
}

// notify invokes the observer (if any), guarding against a nil incident.
func (c *Correlator) notify(ctx context.Context, inc *Incident, opened bool) {
	if c.observer != nil && inc != nil {
		c.observer(ctx, inc, opened)
	}
}

// Ingest correlates a signal into an existing open incident or opens a new one.
// It fails closed if the signal carries no tenant (guardrail 1).
func (c *Correlator) Ingest(ctx context.Context, sig Signal) (*Incident, error) {
	if sig.TenantID == "" {
		return nil, errors.New("incident: signal has no tenant_id")
	}
	now := c.now()
	if sig.OccurredAt.IsZero() {
		sig.OccurredAt = now
	} else if sig.OccurredAt.After(now.Add(MaxFutureSkew)) {
		// CORRECT-009: a far-future event time is clock skew. Clamp it to ingest
		// time so it cannot extend the incident window unboundedly. The original
		// time is preserved on the signal's evidence via the structured log; the
		// correlation/aggregation math uses the clamped value.
		c.log.Warn("clamping future-dated signal OccurredAt (clock skew)",
			"tenant_id", sig.TenantID, "plane", sig.Plane, "kind", sig.Kind,
			"claimed", sig.OccurredAt, "clamped_to", now)
		sig.OccurredAt = now
	}
	if sig.Severity == "" {
		sig.Severity = SeverityInfo
	}

	updated, opened, err := c.correlateLocked(ctx, sig)
	if err != nil {
		return nil, err
	}
	c.notify(ctx, updated, opened)
	return updated, nil
}

func (c *Correlator) correlateLocked(ctx context.Context, sig Signal) (*Incident, bool, error) {
	// CORRECT-013: hold the per-tenant lock across the whole read→correlate→
	// create sequence so concurrent signals for one tenant cannot both open a
	// fresh incident for the same event. Observer work happens after this helper
	// returns, so slow notification connectors cannot hold the tenant lock.
	lock := c.tenantLock(sig.TenantID)
	lock.Lock()
	defer lock.Unlock()

	var (
		updated *Incident
		opened  bool
		err     error
	)
	if txStore, ok := c.store.(TransactionalStore); ok {
		err = txStore.WithTenantCorrelationLock(ctx, sig.TenantID, func(txCtx context.Context, txStore Store) error {
			updated, opened, err = c.ingestWithStore(txCtx, txStore, sig)
			return err
		})
	} else {
		updated, opened, err = c.ingestWithStore(ctx, c.store, sig)
	}
	if err != nil {
		return nil, false, err
	}
	return updated, opened, nil
}

func (c *Correlator) ingestWithStore(ctx context.Context, st Store, sig Signal) (*Incident, bool, error) {
	open, err := st.OpenIncidents(ctx, sig.TenantID)
	if err != nil {
		return nil, false, fmt.Errorf("incident: load open incidents: %w", err)
	}
	for _, inc := range open {
		if related(inc, sig, c.window) {
			updated, err := st.AppendSignal(ctx, sig.TenantID, inc.ID, sig)
			if err != nil {
				return nil, false, fmt.Errorf("incident: append signal: %w", err)
			}
			c.log.Info("signal correlated to incident",
				"incident_id", inc.ID, "plane", sig.Plane, "kind", sig.Kind, "tenant_id", sig.TenantID)
			return updated, false, nil
		}
	}

	created, err := st.Create(ctx, newIncident(sig))
	if err != nil {
		return nil, false, fmt.Errorf("incident: create: %w", err)
	}
	updated, err := st.AppendSignal(ctx, sig.TenantID, created.ID, sig)
	if err != nil {
		return nil, false, fmt.Errorf("incident: append first signal: %w", err)
	}
	c.log.Info("opened incident",
		"incident_id", created.ID, "plane", sig.Plane, "kind", sig.Kind, "tenant_id", sig.TenantID)
	return updated, true, nil
}

// --- in-memory store (lightweight mode + tests) ---

// MemoryStore is an in-process Store.
type MemoryStore struct {
	mu        sync.Mutex
	seq       int
	incidents map[string]*Incident
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{incidents: make(map[string]*Incident)}
}

// OpenIncidents returns the tenant's open incidents, most-recently-active first.
func (m *MemoryStore) OpenIncidents(_ context.Context, tenant string) ([]*Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*Incident
	for _, inc := range m.incidents {
		if inc.TenantID == tenant && inc.Status == StatusOpen {
			out = append(out, inc)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	return out, nil
}

// Create stores a new incident with a generated id.
func (m *MemoryStore) Create(_ context.Context, inc *Incident) (*Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	cp := *inc
	cp.ID = fmt.Sprintf("inc-%d", m.seq)
	m.incidents[cp.ID] = &cp
	return &cp, nil
}

// AppendSignal appends sig and updates the incident's aggregates.
func (m *MemoryStore) AppendSignal(_ context.Context, tenant, incidentID string, sig Signal) (*Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inc, ok := m.incidents[incidentID]
	if !ok || inc.TenantID != tenant {
		return nil, errors.New("incident: not found")
	}
	inc.Signals = append(inc.Signals, sig)
	inc.SignalCount++
	inc.Severity = Max(inc.Severity, sig.Severity)
	if sig.OccurredAt.After(inc.LastSeenAt) {
		inc.LastSeenAt = sig.OccurredAt
	}
	if sig.OccurredAt.Before(inc.StartedAt) {
		inc.StartedAt = sig.OccurredAt
	}
	return inc, nil
}

// Get returns an incident by id (test inspection).
func (m *MemoryStore) Get(id string) *Incident {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.incidents[id]
}

// Len returns the number of stored incidents (test inspection).
func (m *MemoryStore) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.incidents)
}
