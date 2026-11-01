// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package incident

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/entity"
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
	ActiveCorrelationOverrides(ctx context.Context, tenant string, sig Signal) ([]CorrelationOverride, error)
}

// TransactionalStore can serialize the read-correlate-create sequence in the
// durable backing store. HA control-plane replicas do not share Correlator's
// in-process mutex, so Postgres-backed stores use this seam to hold a tenant-keyed
// transaction advisory lock across OpenIncidents/Create/AppendSignal.
type TransactionalStore interface {
	Store
	WithTenantCorrelationLock(ctx context.Context, tenant string, fn func(context.Context, Store) error) error
}

// FaultReceiptStore is available only inside a durable tenant correlation
// transaction. It prevents a re-sent evidence RPC from opening another
// incident after the original one was resolved.
type FaultReceiptStore interface {
	ClaimFaultReceipt(context.Context, AuthenticatedIdentitySource, string, Signal) (*Incident, error)
	CompleteFaultReceipt(context.Context, AuthenticatedIdentitySource, string, string) error
}

var ErrFaultObservationConflict = errors.New("incident: fault observation ID reused with different evidence")
var ErrFaultIdentityInactive = errors.New("incident: fault sender identity is not active for the observation")
var ErrFaultSourceInactive = errors.New("incident: fault source assignment is not active for the observation")

// AuthenticatedIdentitySource is constructed by trusted transport code from
// the mTLS state of an evidence-plane RPC. Its fields are private so a bus
// payload cannot directly stamp a tenant, agent or certificate serial.
// SourceRef remains an observation until the tenant-scoped store confirms its
// current operator assignment. Callers must take TLS state from the live gRPC
// peer, never from a message field or reconstructed certificate.
type AuthenticatedIdentitySource struct {
	tenantID          string
	agentID           string
	sourceKind        string
	sourceRef         string
	certificateSerial string
}

// AuthenticatedSourceFromTLS reads the peer certificate already verified by
// the existing mTLS listener. The caller must pass the live transport state;
// the lookup transaction rechecks the exact issued serial and revocation
// before treating it as current authority.
func AuthenticatedSourceFromTLS(state tls.ConnectionState,
	sourceKind, sourceRef string) (AuthenticatedIdentitySource, error) {
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 ||
		len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 ||
		sourceKind == "" || sourceRef == "" {
		return AuthenticatedIdentitySource{}, errors.New("incident: verified evidence peer is required")
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil || len(leaf.Raw) == 0 ||
		!leaf.Equal(state.VerifiedChains[0][0]) ||
		leaf.SerialNumber == nil || leaf.SerialNumber.Sign() <= 0 ||
		time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return AuthenticatedIdentitySource{}, errors.New("incident: evidence certificate is not current")
	}
	id, err := crypto.EntitySPIFFEIDFromCert(leaf)
	if err != nil {
		return AuthenticatedIdentitySource{}, err
	}
	return AuthenticatedIdentitySource{tenantID: id.TenantID, agentID: id.AgentID,
		sourceKind: sourceKind, sourceRef: sourceRef,
		certificateSerial: leaf.SerialNumber.Text(16)}, nil
}

func (s AuthenticatedIdentitySource) TenantID() string          { return s.tenantID }
func (s AuthenticatedIdentitySource) AgentID() string           { return s.agentID }
func (s AuthenticatedIdentitySource) SourceKind() string        { return s.sourceKind }
func (s AuthenticatedIdentitySource) SourceRef() string         { return s.sourceRef }
func (s AuthenticatedIdentitySource) CertificateSerial() string { return s.certificateSerial }

// IdentityResolution is the result of a store lookup in the correlation
// transaction. ContextID may be set without EntityID when evidence is
// ambiguous; this suppresses raw-address fallback without picking a device.
type IdentityResolution struct {
	ContextID string
	EntityID  string
}

// SignalIdentityResolver is optional for stores that cannot resolve current
// canonical evidence. It must derive context/entity from trusted source
// registration and current evidence inside the tenant correlation transaction.
type SignalIdentityResolver interface {
	ResolveSignalIdentity(context.Context, AuthenticatedIdentitySource, Signal) (IdentityResolution, error)
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
// It fails closed if the signal carries no tenant (guardrail 1) or no
// correlation key (S-9d415bb9).
func (c *Correlator) Ingest(ctx context.Context, sig Signal) (*Incident, error) {
	return c.ingest(ctx, sig, nil, "")
}

// IngestAuthenticated is for a transport that already authenticated an
// evidence-plane sender. A registry error preserves the signal as unresolved
// and prevents raw private-address grouping; raw telemetry admission is not
// coupled to this optional identity lookup.
func (c *Correlator) IngestAuthenticated(ctx context.Context, sig Signal,
	source AuthenticatedIdentitySource) (*Incident, error) {
	if source.tenantID == "" || source.tenantID != sig.TenantID ||
		source.agentID == "" || source.sourceKind == "" ||
		source.sourceRef == "" || source.certificateSerial == "" {
		return nil, errors.New("incident: authenticated identity source is incomplete or tenant-mismatched")
	}
	return c.ingest(ctx, sig, &source, "")
}

// IngestAuthenticatedFault requires a durable tenant receipt. The observation
// UUID is an idempotency key, not a tenant or routing authority. The live TLS
// source and current registry evidence still decide whether identity resolves.
func (c *Correlator) IngestAuthenticatedFault(ctx context.Context, sig Signal,
	source AuthenticatedIdentitySource, observationID string) (*Incident, error) {
	if source.tenantID == "" || source.tenantID != sig.TenantID ||
		source.agentID == "" || source.sourceKind == "" ||
		source.sourceRef == "" || source.certificateSerial == "" {
		return nil, errors.New("incident: authenticated fault source is incomplete or tenant-mismatched")
	}
	id, err := uuid.Parse(observationID)
	if err != nil || id == uuid.Nil || id.Version() != 4 ||
		sig.Attributes[entity.AttrFaultObservationID] != id.String() {
		return nil, errors.New("incident: fault observation ID is invalid or inconsistent")
	}
	if _, ok := c.store.(TransactionalStore); !ok {
		return nil, errors.New("incident: durable fault receipt transaction is required")
	}
	// Resource identity in the incident's OTel-shaped evidence is stamped from
	// the verified peer too; a caller's attribute map cannot impersonate it.
	sig.Attributes = cloneAttributes(sig.Attributes)
	sig.Attributes["probectl.tenant.id"] = source.tenantID
	sig.Attributes["probectl.agent.id"] = source.agentID
	sig.Attributes[entity.AttrSourceKind] = source.sourceKind
	return c.ingest(ctx, sig, &source, id.String())
}

func (c *Correlator) ingest(ctx context.Context, sig Signal,
	source *AuthenticatedIdentitySource, faultObservationID string) (*Incident, error) {
	// These columns are set only by the server-side resolver under the tenant
	// correlation lock. A caller's free-form JSON/attributes cannot stamp them.
	sig.IdentityContextID, sig.IdentityEntityID, sig.IdentityLookupAttempted = "", "", false
	if sig.TenantID == "" {
		return nil, errors.New("incident: signal has no tenant_id")
	}
	// CORRELATION KEY (S-9d415bb9). Relatedness is a target/prefix join, so a
	// signal carrying NEITHER can never correlate with anything: it silently
	// produces one incident per signal and quietly breaks the cross-plane
	// invariant that is the product's headline differentiator. Ingest
	// previously validated only the tenant, so the guarantee rested on every
	// plane REMEMBERING to set a key. Now the boundary refuses the signal and
	// names the plane, so a new plane fails loudly at its first emission
	// instead of degrading correlation for everyone.
	if err := sig.validateCorrelationKey(); err != nil {
		return nil, err
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

	var replayed bool
	updated, opened, err := c.correlateLocked(ctx, sig, source, faultObservationID, &replayed)
	if err != nil {
		return nil, err
	}
	if !replayed {
		c.notify(ctx, updated, opened)
	}
	return updated, nil
}

func (c *Correlator) correlateLocked(ctx context.Context, sig Signal,
	source *AuthenticatedIdentitySource, faultObservationID string, replayed *bool) (*Incident, bool, error) {
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
			updated, opened, err = c.ingestWithStore(txCtx, txStore, sig, source, faultObservationID, replayed)
			return err
		})
	} else {
		updated, opened, err = c.ingestWithStore(ctx, c.store, sig, source, faultObservationID, replayed)
	}
	if err != nil {
		return nil, false, err
	}
	return updated, opened, nil
}

func (c *Correlator) ingestWithStore(ctx context.Context, st Store, sig Signal,
	source *AuthenticatedIdentitySource, faultObservationID string, replayed *bool) (*Incident, bool, error) {
	var receipt FaultReceiptStore
	if faultObservationID != "" {
		var ok bool
		receipt, ok = st.(FaultReceiptStore)
		if !ok || source == nil {
			return nil, false, errors.New("incident: tenant transaction has no fault receipt store")
		}
		prior, err := receipt.ClaimFaultReceipt(ctx, *source, faultObservationID, sig)
		if err != nil {
			return nil, false, err
		}
		if prior != nil {
			*replayed = true
			return prior, false, nil
		}
	}
	if source != nil {
		sig.IdentityLookupAttempted = true
		if resolver, ok := st.(SignalIdentityResolver); ok {
			identity, err := resolver.ResolveSignalIdentity(ctx, *source, sig)
			switch {
			case err != nil:
				c.log.Warn("incident identity lookup unavailable; keeping signal ungrouped",
					"tenant_id", sig.TenantID, "plane", sig.Plane)
			case identity.EntityID == "" || identity.ContextID != "":
				sig.IdentityContextID, sig.IdentityEntityID = identity.ContextID, identity.EntityID
			default:
				c.log.Warn("incident identity lookup returned incomplete tuple; keeping signal ungrouped",
					"tenant_id", sig.TenantID, "plane", sig.Plane)
			}
		}
	}
	overrides, err := st.ActiveCorrelationOverrides(ctx, sig.TenantID, sig)
	if err != nil {
		// An unavailable override store must be loud: silently ignoring operator
		// intent could suppress the very alert they detached.
		return nil, false, fmt.Errorf("incident: load correlation overrides: %w", err)
	}
	open, err := st.OpenIncidents(ctx, sig.TenantID)
	if err != nil {
		return nil, false, fmt.Errorf("incident: load open incidents: %w", err)
	}
	for _, inc := range open {
		if excludedByOverride(inc.ID, overrides) {
			continue
		}
		if related(inc, sig, c.window) {
			sig = withCorrelationExplanation(sig, inc, c.window, overrides)
			updated, err := st.AppendSignal(ctx, sig.TenantID, inc.ID, sig)
			if err != nil {
				return nil, false, fmt.Errorf("incident: append signal: %w", err)
			}
			if receipt != nil {
				if err := receipt.CompleteFaultReceipt(ctx, *source, faultObservationID, updated.ID); err != nil {
					return nil, false, err
				}
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
	sig = withRootCorrelationExplanation(sig, created, overrides)
	updated, err := st.AppendSignal(ctx, sig.TenantID, created.ID, sig)
	if err != nil {
		return nil, false, fmt.Errorf("incident: append first signal: %w", err)
	}
	if receipt != nil {
		if err := receipt.CompleteFaultReceipt(ctx, *source, faultObservationID, updated.ID); err != nil {
			return nil, false, err
		}
	}
	c.log.Info("opened incident",
		"incident_id", created.ID, "plane", sig.Plane, "kind", sig.Kind, "tenant_id", sig.TenantID)
	return updated, true, nil
}

func excludedByOverride(incidentID string, overrides []CorrelationOverride) bool {
	for _, override := range overrides {
		if override.Active && override.SourceIncidentID == incidentID {
			return true
		}
	}
	return false
}

func withCorrelationExplanation(sig Signal, parent *Incident, window time.Duration, overrides []CorrelationOverride) Signal {
	sig.Attributes = cloneAttributes(sig.Attributes)
	sig.Attributes["correlation.state"] = "grouped"
	sig.Attributes["correlation.parent_incident_id"] = parent.ID
	if sig.IdentityLookupAttempted {
		sig.Attributes["correlation.reason"] = "within_window_and_same_verified_entity"
		sig.Attributes["correlation.rule"] = "verified_entity_context_v1"
	} else {
		sig.Attributes["correlation.reason"] = "within_window_and_shared_target_or_prefix"
		sig.Attributes["correlation.rule"] = "time_target_prefix_v1"
	}
	sig.Attributes["correlation.window_seconds"] = fmt.Sprintf("%.0f", window.Seconds())
	freshness := sig.OccurredAt.Sub(parent.LastSeenAt)
	if freshness < 0 {
		freshness = -freshness
	}
	sig.Attributes["correlation.freshness_seconds"] = fmt.Sprintf("%.0f", freshness.Seconds())
	sig.Attributes["correlation.match_confidence"] = "1.00"
	sig.Attributes["correlation.confidence_scope"] = "deterministic_match_not_root_cause_probability"
	if len(overrides) > 0 {
		override := overrides[0]
		sig.Attributes["correlation.override_id"] = override.ID
		sig.Attributes["correlation.excluded_parent_incident_id"] = override.SourceIncidentID
		sig.Attributes["correlation.reason"] = "operator_ungroup_override_then_related_independent_incident"
	}
	return sig
}

func withRootCorrelationExplanation(sig Signal, root *Incident, overrides []CorrelationOverride) Signal {
	sig.Attributes = cloneAttributes(sig.Attributes)
	sig.Attributes["correlation.state"] = "root"
	sig.Attributes["correlation.parent_incident_id"] = root.ID
	sig.Attributes["correlation.reason"] = "no_related_open_incident"
	switch {
	case sig.IdentityEntityID != "":
		sig.Attributes["correlation.rule"] = "verified_entity_context_v1"
	case sig.IdentityLookupAttempted:
		sig.Attributes["correlation.rule"] = "identity_unresolved_v1"
	default:
		sig.Attributes["correlation.rule"] = "time_target_prefix_v1"
	}
	sig.Attributes["correlation.freshness_seconds"] = "0"
	sig.Attributes["correlation.match_confidence"] = "1.00"
	sig.Attributes["correlation.confidence_scope"] = "deterministic_match_not_root_cause_probability"
	if len(overrides) > 0 {
		override := overrides[0]
		sig.Attributes["correlation.override_id"] = override.ID
		sig.Attributes["correlation.excluded_parent_incident_id"] = override.SourceIncidentID
		sig.Attributes["correlation.reason"] = "operator_ungroup_override_created_independent_incident"
	}
	return sig
}

func cloneAttributes(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+8)
	for key, value := range in {
		out[key] = value
	}
	return out
}

// --- in-memory store (lightweight mode + tests) ---

// MemoryStore is an in-process Store.
type MemoryStore struct {
	mu        sync.Mutex
	seq       int
	incidents map[string]*Incident
	overrides map[string]CorrelationOverride
	seen      map[string]map[string]struct{} // incident id -> signal fingerprints (DPR-078)
}

// NewMemoryStore returns an empty in-memory store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{incidents: make(map[string]*Incident), overrides: make(map[string]CorrelationOverride)}
}

func (m *MemoryStore) ActiveCorrelationOverrides(_ context.Context, tenant string, sig Signal) ([]CorrelationOverride, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []CorrelationOverride{}
	for _, override := range m.overrides {
		if override.TenantID == tenant && override.Matches(sig) {
			out = append(out, override)
		}
	}
	return out, nil
}

// putCorrelationOverride is a test/lightweight-mode helper. Production writes
// use the tenant-scoped control API and Postgres repository.
func (m *MemoryStore) putCorrelationOverride(override CorrelationOverride) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.overrides[override.ID] = override
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
	fp := sig.Fingerprint()
	if m.seen == nil {
		m.seen = map[string]map[string]struct{}{}
	}
	if _, dup := m.seen[incidentID][fp]; dup {
		return inc, nil // DPR-078: the timeline already holds this event
	}
	if m.seen[incidentID] == nil {
		m.seen[incidentID] = map[string]struct{}{}
	}
	m.seen[incidentID][fp] = struct{}{}
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

// get returns an incident by id (test inspection).
func (m *MemoryStore) get(id string) *Incident {
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
