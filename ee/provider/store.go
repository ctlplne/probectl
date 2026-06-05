// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
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

	"github.com/imfeelingtheagi/probectl/internal/crypto"
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
	Status         string    `json:"status"` // active | suspended | offboarding | deleted
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

// Store is the provider plane's persistence surface.
type Store interface {
	// Operators.
	CreateOperator(ctx context.Context, op Operator, enrollTokenHash []byte) (Operator, error)
	OperatorByEmail(ctx context.Context, email string) (*Operator, *Credential, error)
	OperatorByEnrollHash(ctx context.Context, hash []byte) (*Operator, error)
	SetOperatorTOTP(ctx context.Context, id string, sealed crypto.Sealed) error
	ActivateOperator(ctx context.Context, id, passwordHash string) error
	SetOperatorStatus(ctx context.Context, id, status string) error
	ListOperators(ctx context.Context) ([]Operator, error)
	CountOperators(ctx context.Context) (int, error)

	// Tenant lifecycle.
	CreateTenant(ctx context.Context, slug, name, isolationModel, residency string) (Tenant, error)
	RenameTenant(ctx context.Context, id, name string) (Tenant, error)
	SetTenantStatus(ctx context.Context, id, status string) (Tenant, error)
	ListTenants(ctx context.Context) ([]Tenant, error)
	CountActiveTenants(ctx context.Context) (int, error)

	// Fleet (counts/versions only — the storage role enforces this in the pg
	// implementation; see migrations/0024 + tenancy.InProvider).
	FleetSummary(ctx context.Context) ([]TenantFleet, error)

	// Break-glass grants.
	CreateGrant(ctx context.Context, g Grant) (Grant, error)
	GetGrant(ctx context.Context, id string) (*Grant, error)
	ListGrants(ctx context.Context) ([]Grant, error)
	ListGrantsForTenant(ctx context.Context, tenantID string) ([]Grant, error)
	ConsentGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error)
	DenyGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error)
	RevokeGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error)
	IncrementGrantUse(ctx context.Context, id string) error
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
	mu        sync.Mutex
	seq       int
	operators map[string]*memOperator
	tenants   map[string]*Tenant
	grants    map[string]*Grant
	fleet     map[string]TenantFleet // keyed by tenant ID; set by tests
}

type memOperator struct {
	op     Operator
	cred   Credential
	enroll []byte
}

// NewMemStore returns an empty in-memory store.
func NewMemStore() *MemStore {
	return &MemStore{
		operators: map[string]*memOperator{},
		tenants:   map[string]*Tenant{},
		grants:    map[string]*Grant{},
		fleet:     map[string]TenantFleet{},
	}
}

func (m *MemStore) nextID(prefix string) string {
	m.seq++
	return fmt.Sprintf("%s_%04d", prefix, m.seq)
}

func (m *MemStore) CreateOperator(_ context.Context, op Operator, enrollTokenHash []byte) (Operator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
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

func (m *MemStore) CreateTenant(_ context.Context, slug, name, isolationModel, residency string) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tenants {
		if t.Slug == slug {
			return Tenant{}, ErrConflict
		}
	}
	if isolationModel == "" {
		isolationModel = "pooled"
	}
	t := Tenant{ID: m.nextID("tn"), Slug: slug, Name: name, Status: "active",
		IsolationModel: isolationModel, Residency: residency, CreatedAt: time.Now().UTC()}
	m.tenants[t.ID] = &t
	return t, nil
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
	out := make([]Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

func (m *MemStore) CountActiveTenants(_ context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, t := range m.tenants {
		if t.Status == "active" || t.Status == "suspended" {
			n++ // suspended tenants still occupy a band slot; offboarded do not
		}
	}
	return n, nil
}

// SetFleet seeds fleet rows (tests).
func (m *MemStore) SetFleet(rows ...TenantFleet) {
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

func (m *MemStore) IncrementGrantUse(_ context.Context, id string) error {
	_, err := m.mutateGrant(id, func(g *Grant) error {
		g.UseCount++
		return nil
	})
	return err
}
