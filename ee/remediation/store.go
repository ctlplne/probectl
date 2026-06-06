// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	rem "github.com/imfeelingtheagi/probectl/internal/remediation"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Store persists remediation proposals (tenant-RLS, S-EE5).
type Store interface {
	Insert(ctx context.Context, tenantID string, p rem.Proposal) (rem.Proposal, error)
	List(ctx context.Context, tenantID string) ([]rem.Proposal, error)
	Get(ctx context.Context, tenantID, id string) (rem.Proposal, error)
	Decide(ctx context.Context, tenantID, id string, state rem.State, by, note string, at time.Time) (rem.Proposal, error)
}

// PGStore is the Postgres store, scoped by tenancy.InTenant (RLS).
type PGStore struct{ pool *pgxpool.Pool }

// NewPGStore wraps a pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

const cols = `id::text, tenant_id::text, kind, title, rationale, target, incident_id,
	dry_run, state, proposed_by, decided_by, decision_note, created_at, decided_at`

func scanProposal(row pgx.Row) (rem.Proposal, error) {
	var (
		p      rem.Proposal
		dryRaw []byte
	)
	if err := row.Scan(&p.ID, &p.TenantID, &p.Kind, &p.Title, &p.Rationale, &p.Target,
		&p.IncidentID, &dryRaw, &p.State, &p.ProposedBy, &p.DecidedBy, &p.Decision,
		&p.CreatedAt, &p.DecidedAt); err != nil {
		return rem.Proposal{}, err
	}
	if len(dryRaw) > 0 {
		_ = json.Unmarshal(dryRaw, &p.DryRun)
	}
	return p, nil
}

func (s *PGStore) Insert(ctx context.Context, tenantID string, p rem.Proposal) (rem.Proposal, error) {
	dry, _ := json.Marshal(p.DryRun)
	var out rem.Proposal
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var e error
		out, e = scanProposal(sc.Q.QueryRow(ctx, `
			INSERT INTO remediation_proposals
				(tenant_id, kind, title, rationale, target, incident_id, dry_run, state, proposed_by, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)
			RETURNING `+cols,
			tenantID, p.Kind, p.Title, p.Rationale, p.Target, p.IncidentID, string(dry), p.State, p.ProposedBy, p.CreatedAt))
		return e
	})
	return out, err
}

func (s *PGStore) List(ctx context.Context, tenantID string) ([]rem.Proposal, error) {
	var out []rem.Proposal
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		rows, err := sc.Q.Query(ctx, `SELECT `+cols+` FROM remediation_proposals ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			p, err := scanProposal(rows)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	return out, err
}

func (s *PGStore) Get(ctx context.Context, tenantID, id string) (rem.Proposal, error) {
	var out rem.Proposal
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var e error
		out, e = scanProposal(sc.Q.QueryRow(ctx, `SELECT `+cols+` FROM remediation_proposals WHERE id = $1`, id))
		if errors.Is(e, pgx.ErrNoRows) {
			return rem.Error{Code: "not_found", Message: "remediation proposal not found"}
		}
		return e
	})
	return out, err
}

func (s *PGStore) Decide(ctx context.Context, tenantID, id string, state rem.State, by, note string, at time.Time) (rem.Proposal, error) {
	var out rem.Proposal
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var e error
		out, e = scanProposal(sc.Q.QueryRow(ctx, `
			UPDATE remediation_proposals
			   SET state = $2, decided_by = $3, decision_note = $4, decided_at = $5
			 WHERE id = $1 AND state = 'proposed'
			RETURNING `+cols, id, state, by, note, at))
		if errors.Is(e, pgx.ErrNoRows) {
			return rem.ErrNotProposed // someone else decided it, or it's gone
		}
		return e
	})
	return out, err
}

// MemStore is an in-memory Store (unit tests).
type MemStore struct {
	mu  sync.Mutex
	seq int
	all map[string][]rem.Proposal // tenant -> proposals
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore { return &MemStore{all: map[string][]rem.Proposal{}} }

func (m *MemStore) Insert(_ context.Context, tenantID string, p rem.Proposal) (rem.Proposal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	p.ID = "rem-" + itoa(m.seq)
	p.TenantID = tenantID
	m.all[tenantID] = append(m.all[tenantID], p)
	return p, nil
}

func (m *MemStore) List(_ context.Context, tenantID string) ([]rem.Proposal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := append([]rem.Proposal(nil), m.all[tenantID]...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemStore) Get(_ context.Context, tenantID, id string) (rem.Proposal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.all[tenantID] {
		if p.ID == id {
			return p, nil
		}
	}
	return rem.Proposal{}, rem.Error{Code: "not_found", Message: "remediation proposal not found"}
}

func (m *MemStore) Decide(_ context.Context, tenantID, id string, state rem.State, by, note string, at time.Time) (rem.Proposal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.all[tenantID] {
		if m.all[tenantID][i].ID != id {
			continue
		}
		if m.all[tenantID][i].State != rem.StateProposed {
			return rem.Proposal{}, rem.ErrNotProposed
		}
		m.all[tenantID][i].State = state
		m.all[tenantID][i].DecidedBy = by
		m.all[tenantID][i].Decision = note
		t := at
		m.all[tenantID][i].DecidedAt = &t
		return m.all[tenantID][i], nil
	}
	return rem.Proposal{}, rem.Error{Code: "not_found", Message: "remediation proposal not found"}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
