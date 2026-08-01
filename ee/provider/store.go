// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
)

// The provider plane's data model (S-T1). Tenants/operators/grants live in
// Postgres (the S2 schema + the 0024 extensions); Store abstracts them so the
// service logic is unit-testable and the pgx implementation stays thin.

// Operator is a provider-plane operator — NOT a tenant user (a distinct
// privilege domain; CLAUDE.md §7 guardrail 1). Enrolled reports whether the
// operator completed enrollment (set a password + bound an authenticator).
type Operator struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`   // admin | operator (separation of duties)
	Status    string    `json:"status"` // active | suspended | disabled
	Enrolled  bool      `json:"enrolled"`
	CreatedAt time.Time `json:"created_at"`
}

// Operator roles (SoD): admins manage operators; operators run tenant
// lifecycle + break-glass. Admins hold both powers.
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
)

// Credential is an operator's verification material: the one-way password
// record and the envelope-sealed TOTP secret. It never leaves the package.
type Credential struct {
	PasswordHash string
	TOTP         crypto.Sealed
}

// Tenant is the provider-plane view of a tenant (lifecycle metadata only —
// never telemetry). IsolationModel and Residency are the S-T2 fields: which
// isolation model the tenant runs under (pooled is the default) and the
// data-plane name it is pinned to ("" = the default plane).
type Tenant struct {
	ID             string    `json:"id"`
	Slug           string    `json:"slug"`
	Name           string    `json:"name"`
	Status         string    `json:"status"` // provisioning | active | suspended | offboarding | deleted
	IsolationModel string    `json:"isolation_model"`
	Residency      string    `json:"residency,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// TenantFleet is one tenant's agent-fleet health: counts and versions,
// deliberately nothing more (the no-implicit-telemetry rule).
type TenantFleet struct {
	TenantID     string         `json:"tenant_id"`
	TenantSlug   string         `json:"tenant_slug"`
	TenantName   string         `json:"tenant_name"`
	TenantStatus string         `json:"tenant_status"`
	AgentsTotal  int            `json:"agents_total"`
	AgentsOnline int            `json:"agents_online"`
	AgentsStale  int            `json:"agents_stale"` // online but last seen > 5m ago
	Versions     map[string]int `json:"versions"`
}

// Grant is a break-glass grant: explicit, time-bounded, tenant-consented,
// separately audited. Its effective state is derived, never stored, so an
// expired grant can never read as active.
type Grant struct {
	ID            string     `json:"id"`
	OperatorID    string     `json:"operator_id"`
	OperatorEmail string     `json:"operator_email"`
	TenantID      string     `json:"tenant_id"`
	Reason        string     `json:"reason"`
	Scope         string     `json:"scope"` // read (write scopes are out of S-T1 scope)
	GrantedBy     string     `json:"granted_by"`
	GrantedAt     time.Time  `json:"granted_at"`
	ExpiresAt     time.Time  `json:"expires_at"`
	ConsentedBy   string     `json:"consented_by,omitempty"`
	ConsentedAt   *time.Time `json:"consented_at,omitempty"`
	DeniedBy      string     `json:"denied_by,omitempty"`
	DeniedAt      *time.Time `json:"denied_at,omitempty"`
	RevokedBy     string     `json:"revoked_by,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	UseCount      int        `json:"use_count"`
}

// Grant states.
const (
	GrantPending = "pending" // awaiting tenant consent
	GrantActive  = "active"  // consented, unexpired, unrevoked — usable
	GrantDenied  = "denied"
	GrantRevoked = "revoked"
	GrantExpired = "expired"
)

// State derives the grant's effective state at time t.
func (g Grant) State(t time.Time) string {
	switch {
	case g.RevokedAt != nil:
		return GrantRevoked
	case g.DeniedAt != nil:
		return GrantDenied
	case !g.ExpiresAt.After(t):
		return GrantExpired
	case g.ConsentedAt == nil:
		return GrantPending
	default:
		return GrantActive
	}
}

// Usable reports whether the grant authorizes a break-glass read at t.
func (g Grant) Usable(t time.Time) bool { return g.State(t) == GrantActive }

// MutationStore is the write surface available inside an audited provider
// transaction. Reads remain on Store so callers cannot accidentally stretch a
// write transaction across unrelated work.
type MutationStore interface {
	CreateOperator(ctx context.Context, op Operator, enrollTokenHash []byte) (Operator, error)
	// BootstrapOperator inserts only when the provider roster is empty. The
	// production implementation serializes that predicate at the database.
	BootstrapOperator(ctx context.Context, op Operator, enrollTokenHash []byte) (Operator, error)
	SetOperatorTOTP(ctx context.Context, id string, sealed crypto.Sealed) error
	ActivateOperator(ctx context.Context, id, passwordHash string) error
	SetOperatorStatus(ctx context.Context, id, status string) error
	CreateTenant(ctx context.Context, slug, name, isolationModel, residency string, tenantBand int) (Tenant, error)
	CreateTenantProvision(ctx context.Context, slug, name, isolationModel, residency string) (Tenant, error)
	CompleteTenantProvision(ctx context.Context, id string, tenantBand int) (Tenant, bool, error)
	// RecordProvisionAttempt updates a stranded attempt's step ledger: how far
	// it got and why it stopped (S-fadcec95). Operators decide retry-vs-abandon
	// on that evidence rather than on a guess.
	RecordProvisionAttempt(ctx context.Context, id, step, failure string) error
	// AbandonProvision removes a staging row whose external legs have been
	// compensated. It is the ONLY way a provisioning row leaves the table
	// other than completion, so an abandoned attempt is always deliberate.
	AbandonProvision(ctx context.Context, id string) (bool, error)
	RenameTenant(ctx context.Context, id, name string) (Tenant, error)
	SetTenantStatus(ctx context.Context, id, status string) (Tenant, error)
	CreateGrant(ctx context.Context, g Grant) (Grant, error)
	ConsentGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error)
	DenyGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error)
	RevokeGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error)
	UseGrant(ctx context.Context, id, operatorID string, at time.Time) (*Grant, error)
}

// AuditedMutation runs a provider write and its mandatory audit append as one
// unit. Production executes it in one provider-scoped PostgreSQL transaction;
// MemStore stages its copy and publishes it only after the audit succeeds.
type AuditedMutation func(context.Context, MutationStore, AuditSink) error

// StrandedProvision is a provisioning attempt that never completed: the
// staging row plus how far it got and why it stopped. A tenant is not
// routable and consumes no band slot while in this state.
type StrandedProvision struct {
	ID             string    `json:"id"`
	Slug           string    `json:"slug"`
	Name           string    `json:"name"`
	IsolationModel string    `json:"isolation_model"`
	Residency      string    `json:"residency"`
	CreatedAt      time.Time `json:"created_at"`
	LastAttemptAt  time.Time `json:"last_attempt_at"`
	LastStep       string    `json:"last_step"`
	LastError      string    `json:"last_error,omitempty"`
}

// Store is the provider plane's persistence surface.
type Store interface {
	MutationStore

	// WithAuditedMutation must commit the mutation and provider audit event
	// together or leave both unchanged.
	WithAuditedMutation(ctx context.Context, sink AuditSink, fn AuditedMutation) error

	// Operators.
	OperatorByEmail(ctx context.Context, email string) (*Operator, *Credential, error)
	OperatorByEnrollHash(ctx context.Context, hash []byte) (*Operator, error)
	ListOperators(ctx context.Context) ([]Operator, error)
	CountOperators(ctx context.Context) (int, error)

	// Tenant lifecycle.
	ListTenants(ctx context.Context) ([]Tenant, error)
	// ListStrandedProvisions returns provisioning attempts whose last attempt
	// is older than age — the rows an operator (or the reaper) must act on.
	ListStrandedProvisions(ctx context.Context, age time.Duration) ([]StrandedProvision, error)
	TenantBySlug(ctx context.Context, slug string) (*Tenant, error)
	CountActiveTenants(ctx context.Context) (int, error)

	// Fleet (counts/versions only — the storage role enforces this in the pg
	// implementation; see migrations/0024 + tenancy.InProvider).
	FleetSummary(ctx context.Context) ([]TenantFleet, error)

	// Break-glass grants.
	GetGrant(ctx context.Context, id string) (*Grant, error)
	ListGrants(ctx context.Context) ([]Grant, error)
	ListGrantsForTenant(ctx context.Context, tenantID string) ([]Grant, error)
}

// ErrNotFound is the store's uniform missing-row error.
var ErrNotFound = errors.New("provider: not found")

// ErrConflict marks uniqueness violations (duplicate slug/email).
var ErrConflict = errors.New("provider: conflict")

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// ValidSlug reports whether s is an acceptable tenant slug.
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// --- In-memory implementation (unit tests; the pg implementation is the
// production path and is exercised by the integration-tagged suite). ---

// MemStore is a thread-safe in-memory Store.
type MemStore struct {
	mu         sync.Mutex
	seq        int
	operators  map[string]*memOperator
	tenants    map[string]*Tenant
	provisions map[string]*Tenant
	// ledger records how far each in-flight provision got and why it stopped
	// (S-fadcec95), keyed by the same id as provisions.
	ledger map[string]StrandedProvision
	grants map[string]*Grant
	fleet  map[string]TenantFleet // keyed by tenant ID; set by tests
}

type memOperator struct {
	op     Operator
	cred   Credential
	enroll []byte
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		operators:  map[string]*memOperator{},
		tenants:    map[string]*Tenant{},
		provisions: map[string]*Tenant{},
		grants:     map[string]*Grant{},
		fleet:      map[string]TenantFleet{},
	}
}

// WithAuditedMutation stages changes in an isolated copy. The live maps are
// swapped only after the audit sink succeeds, which gives unit tests the same
// all-or-nothing contract as the PostgreSQL implementation.
func (m *MemStore) WithAuditedMutation(ctx context.Context, sink AuditSink, fn AuditedMutation) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	staged := m.cloneLocked()
	if err := fn(ctx, staged, sink); err != nil {
		return err
	}
	m.seq = staged.seq
	m.operators = staged.operators
	m.tenants = staged.tenants
	m.provisions = staged.provisions
	m.grants = staged.grants
	m.fleet = staged.fleet
	return nil
}

func (m *MemStore) cloneLocked() *MemStore {
	staged := NewMemStore()
	staged.seq = m.seq
	for id, x := range m.operators {
		cp := &memOperator{
			op:     x.op,
			cred:   x.cred,
			enroll: append([]byte(nil), x.enroll...),
		}
		cp.cred.TOTP.WrappedDEK = append([]byte(nil), x.cred.TOTP.WrappedDEK...)
		cp.cred.TOTP.Ciphertext = append([]byte(nil), x.cred.TOTP.Ciphertext...)
		staged.operators[id] = cp
	}
	for id, tenant := range m.tenants {
		cp := *tenant
		staged.tenants[id] = &cp
	}
	for id, tenant := range m.provisions {
		cp := *tenant
		staged.provisions[id] = &cp
	}
	for id, grant := range m.grants {
		cp := *grant
		cp.ConsentedAt = cloneTime(grant.ConsentedAt)
		cp.DeniedAt = cloneTime(grant.DeniedAt)
		cp.RevokedAt = cloneTime(grant.RevokedAt)
		staged.grants[id] = &cp
	}
	for id, fleet := range m.fleet {
		cp := fleet
		cp.Versions = make(map[string]int, len(fleet.Versions))
		for version, count := range fleet.Versions {
			cp.Versions[version] = count
		}
		staged.fleet[id] = cp
	}
	return staged
}

func cloneTime(in *time.Time) *time.Time {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func (m *MemStore) nextID(prefix string) string {
	m.seq++
	return fmt.Sprintf("%s_%04d", prefix, m.seq)
}

func (m *MemStore) CreateOperator(_ context.Context, op Operator, enrollTokenHash []byte) (Operator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.createOperatorLocked(op, enrollTokenHash)
}

func (m *MemStore) BootstrapOperator(_ context.Context, op Operator, enrollTokenHash []byte) (Operator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.operators) != 0 {
		return Operator{}, ErrConflict
	}
	return m.createOperatorLocked(op, enrollTokenHash)
}

func (m *MemStore) createOperatorLocked(op Operator, enrollTokenHash []byte) (Operator, error) {
	for _, x := range m.operators {
		if strings.EqualFold(x.op.Email, op.Email) {
			return Operator{}, ErrConflict
		}
	}
	op.ID = m.nextID("op")
	op.CreatedAt = time.Now().UTC()
	m.operators[op.ID] = &memOperator{op: op, enroll: enrollTokenHash}
	return op, nil
}

func (m *MemStore) OperatorByEmail(_ context.Context, email string) (*Operator, *Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.operators {
		if strings.EqualFold(x.op.Email, email) {
			op, cred := x.op, x.cred
			return &op, &cred, nil
		}
	}
	return nil, nil, ErrNotFound
}

func (m *MemStore) OperatorByEnrollHash(_ context.Context, hash []byte) (*Operator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.operators {
		if len(x.enroll) > 0 && crypto.ConstantTimeEqual(x.enroll, hash) {
			op := x.op
			return &op, nil
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) SetOperatorTOTP(_ context.Context, id string, sealed crypto.Sealed) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.operators[id]
	if !ok {
		return ErrNotFound
	}
	x.cred.TOTP = sealed
	return nil
}

func (m *MemStore) ActivateOperator(_ context.Context, id, passwordHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.operators[id]
	if !ok {
		return ErrNotFound
	}
	x.cred.PasswordHash = passwordHash
	x.op.Enrolled = true
	x.op.Status = "active"
	x.enroll = nil // the enrollment token is single-use
	return nil
}

func (m *MemStore) SetOperatorStatus(_ context.Context, id, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.operators[id]
	if !ok {
		return ErrNotFound
	}
	x.op.Status = status
	return nil
}

func (m *MemStore) ListOperators(_ context.Context) ([]Operator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Operator, 0, len(m.operators))
	for _, x := range m.operators {
		out = append(out, x.op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Email < out[j].Email })
	return out, nil
}

func (m *MemStore) CountOperators(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.operators), nil
}

func (m *MemStore) CreateTenant(
	_ context.Context,
	slug, name, isolationModel, residency string,
	tenantBand int,
) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tenantBand > 0 && m.activeTenantCountLocked() >= tenantBand {
		return Tenant{}, ErrBandExhausted
	}
	for _, t := range m.tenants {
		if t.Slug == slug {
			return Tenant{}, ErrConflict
		}
	}
	for _, t := range m.provisions {
		if t.Slug == slug {
			return Tenant{}, ErrConflict
		}
	}
	if isolationModel == "" {
		isolationModel = "pooled"
	}
	if isolationModel != "pooled" {
		return Tenant{}, errors.New("provider: isolated tenants must use resumable provisioning")
	}
	t := Tenant{ID: m.nextID("tn"), Slug: slug, Name: name, Status: "active",
		IsolationModel: isolationModel, Residency: residency, CreatedAt: time.Now().UTC()}
	m.tenants[t.ID] = &t
	return t, nil
}

func (m *MemStore) CreateTenantProvision(
	_ context.Context,
	slug, name, isolationModel, residency string,
) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if isolationModel != "siloed" && isolationModel != "hybrid" {
		return Tenant{}, errors.New("provider: resumable provisioning requires siloed or hybrid isolation")
	}
	for _, tenants := range []map[string]*Tenant{m.tenants, m.provisions} {
		for _, t := range tenants {
			if t.Slug == slug {
				return Tenant{}, ErrConflict
			}
		}
	}
	t := Tenant{
		ID: m.nextID("tn"), Slug: slug, Name: name, Status: "provisioning",
		IsolationModel: isolationModel, Residency: residency, CreatedAt: time.Now().UTC(),
	}
	m.provisions[t.ID] = &t
	return t, nil
}

// RecordProvisionAttempt updates the in-memory step ledger.
func (m *MemStore) RecordProvisionAttempt(_ context.Context, id, step, failure string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.provisions[id]
	if !ok {
		return ErrNotFound
	}
	if m.ledger == nil {
		m.ledger = map[string]StrandedProvision{}
	}
	entry := m.ledger[id]
	entry.ID, entry.Slug, entry.Name = t.ID, t.Slug, t.Name
	entry.IsolationModel, entry.Residency, entry.CreatedAt = t.IsolationModel, t.Residency, t.CreatedAt
	entry.LastStep, entry.LastError, entry.LastAttemptAt = step, failure, time.Now().UTC()
	m.ledger[id] = entry
	return nil
}

// AbandonProvision removes a staging row and its ledger entry.
func (m *MemStore) AbandonProvision(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.provisions[id]; !ok {
		return false, nil
	}
	delete(m.provisions, id)
	delete(m.ledger, id)
	return true, nil
}

// ListStrandedProvisions returns in-flight attempts last touched before the
// age cutoff (age <= 0 lists them all), newest first.
func (m *MemStore) ListStrandedProvisions(_ context.Context, age time.Duration) ([]StrandedProvision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cutoff := time.Now().Add(-age)
	var out []StrandedProvision
	for id, t := range m.provisions {
		entry, ok := m.ledger[id]
		if !ok {
			entry = StrandedProvision{
				ID: t.ID, Slug: t.Slug, Name: t.Name,
				IsolationModel: t.IsolationModel, Residency: t.Residency,
				CreatedAt: t.CreatedAt, LastAttemptAt: t.CreatedAt, LastStep: "registered",
			}
		}
		if age > 0 && entry.LastAttemptAt.After(cutoff) {
			continue
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastAttemptAt.After(out[j].LastAttemptAt) })
	return out, nil
}

func (m *MemStore) CompleteTenantProvision(
	_ context.Context,
	id string,
	tenantBand int,
) (Tenant, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.provisions[id]; ok {
		if tenantBand > 0 && m.activeTenantCountLocked() >= tenantBand {
			return Tenant{}, false, ErrBandExhausted
		}
		delete(m.provisions, id)
		t.Status = "active"
		m.tenants[id] = t
		return *t, true, nil
	}
	if t, ok := m.tenants[id]; ok && t.Status == "active" {
		return *t, false, nil
	}
	return Tenant{}, false, ErrNotFound
}

func (m *MemStore) RenameTenant(_ context.Context, id, name string) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	t.Name = name
	return *t, nil
}

func (m *MemStore) SetTenantStatus(_ context.Context, id, status string) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	t.Status = status
	return *t, nil
}

func (m *MemStore) ListTenants(_ context.Context) ([]Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Tenant, 0, len(m.tenants)+len(m.provisions))
	for _, t := range m.tenants {
		out = append(out, *t)
	}
	for _, t := range m.provisions {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func (m *MemStore) TenantBySlug(_ context.Context, slug string) (*Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tenants := range []map[string]*Tenant{m.tenants, m.provisions} {
		for _, t := range tenants {
			if t.Slug == slug {
				cp := *t
				return &cp, nil
			}
		}
	}
	return nil, ErrNotFound
}

func (m *MemStore) CountActiveTenants(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.activeTenantCountLocked(), nil
}

func (m *MemStore) activeTenantCountLocked() int {
	n := 0
	for _, t := range m.tenants {
		if t.Status == "active" || t.Status == "suspended" {
			n++ // suspended tenants still occupy a band slot; offboarded do not
		}
	}
	return n
}

// setFleet seeds fleet rows (tests).
func (m *MemStore) setFleet(rows ...TenantFleet) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rows {
		m.fleet[r.TenantID] = r
	}
}

func (m *MemStore) FleetSummary(_ context.Context) ([]TenantFleet, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TenantFleet, 0, len(m.tenants))
	for id, t := range m.tenants {
		row, ok := m.fleet[id]
		if !ok {
			row = TenantFleet{Versions: map[string]int{}}
		}
		row.TenantID, row.TenantSlug, row.TenantName, row.TenantStatus = id, t.Slug, t.Name, t.Status
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].TenantSlug < out[j].TenantSlug })
	return out, nil
}

func (m *MemStore) CreateGrant(_ context.Context, g Grant) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g.ID = m.nextID("bg")
	m.grants[g.ID] = &g
	return g, nil
}

func (m *MemStore) GetGrant(_ context.Context, id string) (*Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *g
	return &cp, nil
}

func (m *MemStore) ListGrants(_ context.Context) ([]Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Grant, 0, len(m.grants))
	for _, g := range m.grants {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantedAt.After(out[j].GrantedAt) })
	return out, nil
}

func (m *MemStore) ListGrantsForTenant(_ context.Context, tenantID string) ([]Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Grant
	for _, g := range m.grants {
		if g.TenantID == tenantID {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GrantedAt.After(out[j].GrantedAt) })
	return out, nil
}

func (m *MemStore) mutateGrant(id string, fn func(*Grant) error) (*Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.grants[id]
	if !ok {
		return nil, ErrNotFound
	}
	if err := fn(g); err != nil {
		return nil, err
	}
	cp := *g
	return &cp, nil
}

func (m *MemStore) ConsentGrant(_ context.Context, id, by string, at time.Time) (*Grant, error) {
	return m.mutateGrant(id, func(g *Grant) error {
		g.ConsentedBy, g.ConsentedAt = by, &at
		return nil
	})
}

func (m *MemStore) DenyGrant(_ context.Context, id, by string, at time.Time) (*Grant, error) {
	return m.mutateGrant(id, func(g *Grant) error {
		g.DeniedBy, g.DeniedAt = by, &at
		return nil
	})
}

func (m *MemStore) RevokeGrant(_ context.Context, id, by string, at time.Time) (*Grant, error) {
	return m.mutateGrant(id, func(g *Grant) error {
		g.RevokedBy, g.RevokedAt = by, &at
		return nil
	})
}

func (m *MemStore) UseGrant(_ context.Context, id, operatorID string, at time.Time) (*Grant, error) {
	return m.mutateGrant(id, func(g *Grant) error {
		if g.OperatorID != operatorID {
			return ErrNotGrantee
		}
		if !g.Usable(at) {
			return fmt.Errorf("%w (state: %s)", ErrNotConsented, g.State(at))
		}
		g.UseCount++
		return nil
	})
}
