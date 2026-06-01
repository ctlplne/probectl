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

// Correlator groups incoming signals into incidents.
type Correlator struct {
	store  Store
	window time.Duration
	log    *slog.Logger
}

// NewCorrelator builds a correlator over store with the given time window.
func NewCorrelator(store Store, window time.Duration, log *slog.Logger) *Correlator {
	if window <= 0 {
		window = DefaultWindow
	}
	if log == nil {
		log = slog.Default()
	}
	return &Correlator{store: store, window: window, log: log}
}

// Ingest correlates a signal into an existing open incident or opens a new one.
// It fails closed if the signal carries no tenant (guardrail 1).
func (c *Correlator) Ingest(ctx context.Context, sig Signal) (*Incident, error) {
	if sig.TenantID == "" {
		return nil, errors.New("incident: signal has no tenant_id")
	}
	if sig.OccurredAt.IsZero() {
		sig.OccurredAt = time.Now()
	}
	if sig.Severity == "" {
		sig.Severity = SeverityInfo
	}

	open, err := c.store.OpenIncidents(ctx, sig.TenantID)
	if err != nil {
		return nil, fmt.Errorf("incident: load open incidents: %w", err)
	}
	for _, inc := range open {
		if related(inc, sig, c.window) {
			updated, err := c.store.AppendSignal(ctx, sig.TenantID, inc.ID, sig)
			if err != nil {
				return nil, fmt.Errorf("incident: append signal: %w", err)
			}
			c.log.Info("signal correlated to incident",
				"incident_id", inc.ID, "plane", sig.Plane, "kind", sig.Kind, "tenant_id", sig.TenantID)
			return updated, nil
		}
	}

	created, err := c.store.Create(ctx, newIncident(sig))
	if err != nil {
		return nil, fmt.Errorf("incident: create: %w", err)
	}
	updated, err := c.store.AppendSignal(ctx, sig.TenantID, created.ID, sig)
	if err != nil {
		return nil, fmt.Errorf("incident: append first signal: %w", err)
	}
	c.log.Info("opened incident",
		"incident_id", created.ID, "plane", sig.Plane, "kind", sig.Kind, "tenant_id", sig.TenantID)
	return updated, nil
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
