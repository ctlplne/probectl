// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	coreaudit "github.com/ctlplne/probectl/internal/audit"
	rem "github.com/ctlplne/probectl/internal/remediation"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// AuditEvent describes the mandatory tenant audit record paired with one
// remediation mutation. InsertAudited fills an empty Target with the generated
// proposal ID; DecideAudited adds the persisted blast radius to Data.
type AuditEvent struct {
	Actor  string
	Action string
	Target string
	Data   map[string]any
}

// Store persists remediation proposals (tenant-RLS, S-EE5).
type Store interface {
	InsertAudited(ctx context.Context, tenantID string, p rem.Proposal, sink AuditSink, event AuditEvent) (rem.Proposal, error)
	List(ctx context.Context, tenantID string) ([]rem.Proposal, error)
	Get(ctx context.Context, tenantID, id string) (rem.Proposal, error)
	DecideAudited(ctx context.Context, tenantID, id string, state rem.State, by, note string, at time.Time, sink AuditSink, event AuditEvent) (rem.Proposal, error)
}

// PGStore is the Postgres store, scoped by tenancy.InTenant (RLS).
type PGStore struct{ pool *pgxpool.Pool }

// NewPGStore wraps a pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

type scopedAuditSink interface {
	AuditSink
	appendScoped(context.Context, tenancy.Scope, string, string, string, map[string]any) error
}

type tenantAudit struct{ pool *pgxpool.Pool }

// NewTenantAudit returns the production tenant audit sink. Its scoped append is
// consumed by PGStore so the remediation row and audit row share one RLS-bound
// PostgreSQL transaction. Standalone blocked-attempt events use Append, which
// opens their own tenant transaction because there is no mutation to pair.
func NewTenantAudit(pool *pgxpool.Pool) AuditSink { return tenantAudit{pool: pool} }

func (a tenantAudit) Append(ctx context.Context, tenantID, actor, action, target string, data map[string]any) error {
	scoped, err := remediationTenantContext(ctx, tenantID)
	if err != nil {
		return err
	}
	if a.pool == nil {
		return errAuditUnavailable
	}
	return tenancy.InTenant(scoped, a.pool, func(ctx context.Context, sc tenancy.Scope) error {
		return a.appendScoped(ctx, sc, actor, action, target, data)
	})
}

func (tenantAudit) appendScoped(ctx context.Context, sc tenancy.Scope, actor, action, target string, data map[string]any) error {
	_, err := coreaudit.TenantAppend(ctx, sc, actor, action, target, data)
	return err
}

func remediationTenantContext(ctx context.Context, tenantID string) (context.Context, error) {
	if tenantID == "" {
		return nil, tenancy.ErrNoTenant
	}
	if bound, ok := tenancy.FromContext(ctx); ok && bound.String() != tenantID {
		return nil, fmt.Errorf("remediation: tenant %q does not match request scope %q", tenantID, bound)
	}
	return tenancy.WithTenant(ctx, tenancy.ID(tenantID)), nil
}

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
		if err := json.Unmarshal(dryRaw, &p.DryRun); err != nil {
			return rem.Proposal{}, fmt.Errorf("remediation proposal %s dry_run is corrupt: %w", p.ID, err)
		}
	}
	return p, nil
}

func (s *PGStore) Insert(ctx context.Context, tenantID string, p rem.Proposal) (rem.Proposal, error) {
	dry, err := json.Marshal(p.DryRun)
	if err != nil {
		return rem.Proposal{}, fmt.Errorf("marshal remediation dry_run: %w", err)
	}
	scoped, err := remediationTenantContext(ctx, tenantID)
	if err != nil {
		return rem.Proposal{}, err
	}
	var out rem.Proposal
	err = tenancy.InTenant(scoped, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = insertProposal(ctx, sc.Q, tenantID, p, dry)
		return err
	})
	return out, err
}

func (s *PGStore) InsertAudited(
	ctx context.Context,
	tenantID string,
	p rem.Proposal,
	sink AuditSink,
	event AuditEvent,
) (rem.Proposal, error) {
	txAudit, ok := sink.(scopedAuditSink)
	if !ok {
		return rem.Proposal{}, errAuditUnavailable
	}
	dry, err := json.Marshal(p.DryRun)
	if err != nil {
		return rem.Proposal{}, fmt.Errorf("marshal remediation dry_run: %w", err)
	}
	scoped, err := remediationTenantContext(ctx, tenantID)
	if err != nil {
		return rem.Proposal{}, err
	}
	var out rem.Proposal
	err = tenancy.InTenant(scoped, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = insertProposal(ctx, sc.Q, tenantID, p, dry)
		if err != nil {
			return err
		}
		target := event.Target
		if target == "" {
			target = out.ID
		}
		return txAudit.appendScoped(ctx, sc, event.Actor, event.Action, target, event.Data)
	})
	return out, err
}

func insertProposal(ctx context.Context, q tenancy.Querier, tenantID string, p rem.Proposal, dry []byte) (rem.Proposal, error) {
	return scanProposal(q.QueryRow(ctx, `
		INSERT INTO remediation_proposals
			(tenant_id, kind, title, rationale, target, incident_id, dry_run, state, proposed_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)
		RETURNING `+cols,
		tenantID, p.Kind, p.Title, p.Rationale, p.Target, p.IncidentID, string(dry), p.State, p.ProposedBy, p.CreatedAt))
}

func (s *PGStore) List(ctx context.Context, tenantID string) ([]rem.Proposal, error) {
	scoped, err := remediationTenantContext(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var out []rem.Proposal
	err = tenancy.InTenant(scoped, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
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
	scoped, err := remediationTenantContext(ctx, tenantID)
	if err != nil {
		return rem.Proposal{}, err
	}
	var out rem.Proposal
	err = tenancy.InTenant(scoped, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
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
	scoped, err := remediationTenantContext(ctx, tenantID)
	if err != nil {
		return rem.Proposal{}, err
	}
	var out rem.Proposal
	err = tenancy.InTenant(scoped, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = decideProposal(ctx, sc.Q, id, state, by, note, at)
		return err
	})
	return out, err
}

func (s *PGStore) DecideAudited(
	ctx context.Context,
	tenantID, id string,
	state rem.State,
	by, note string,
	at time.Time,
	sink AuditSink,
	event AuditEvent,
) (rem.Proposal, error) {
	txAudit, ok := sink.(scopedAuditSink)
	if !ok {
		return rem.Proposal{}, errAuditUnavailable
	}
	scoped, err := remediationTenantContext(ctx, tenantID)
	if err != nil {
		return rem.Proposal{}, err
	}
	var out rem.Proposal
	err = tenancy.InTenant(scoped, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		out, err = decideProposal(ctx, sc.Q, id, state, by, note, at)
		if err != nil {
			return err
		}
		return txAudit.appendScoped(ctx, sc, event.Actor, event.Action, event.Target, auditData(event.Data, out))
	})
	return out, err
}

func decideProposal(ctx context.Context, q tenancy.Querier, id string, state rem.State, by, note string, at time.Time) (rem.Proposal, error) {
	out, err := scanProposal(q.QueryRow(ctx, `
		UPDATE remediation_proposals
		   SET state = $2, decided_by = $3, decision_note = $4, decided_at = $5
		 WHERE id = $1 AND state = 'proposed'
		RETURNING `+cols, id, state, by, note, at))
	if errors.Is(err, pgx.ErrNoRows) {
		return rem.Proposal{}, rem.ErrNotProposed // someone else decided it, or it's gone
	}
	return out, err
}

func auditData(data map[string]any, p rem.Proposal) map[string]any {
	out := make(map[string]any, len(data)+1)
	for key, value := range data {
		out[key] = value
	}
	out["blast_radius"] = p.DryRun.BlastRadius
	return out
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
	return m.insertLocked(tenantID, p), nil
}

func (m *MemStore) insertLocked(tenantID string, p rem.Proposal) rem.Proposal {
	m.seq++
	p.ID = "rem-" + itoa(m.seq)
	p.TenantID = tenantID
	m.all[tenantID] = append(m.all[tenantID], p)
	return p
}

func (m *MemStore) InsertAudited(
	ctx context.Context,
	tenantID string,
	p rem.Proposal,
	sink AuditSink,
	event AuditEvent,
) (rem.Proposal, error) {
	if sink == nil {
		return rem.Proposal{}, errAuditUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	staged := m.cloneLocked()
	out := staged.insertLocked(tenantID, p)
	target := event.Target
	if target == "" {
		target = out.ID
	}
	if err := sink.Append(ctx, tenantID, event.Actor, event.Action, target, event.Data); err != nil {
		return rem.Proposal{}, err
	}
	m.publishLocked(staged)
	return out, nil
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
	return m.decideLocked(tenantID, id, state, by, note, at)
}

func (m *MemStore) decideLocked(tenantID, id string, state rem.State, by, note string, at time.Time) (rem.Proposal, error) {
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

func (m *MemStore) DecideAudited(
	ctx context.Context,
	tenantID, id string,
	state rem.State,
	by, note string,
	at time.Time,
	sink AuditSink,
	event AuditEvent,
) (rem.Proposal, error) {
	if sink == nil {
		return rem.Proposal{}, errAuditUnavailable
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	staged := m.cloneLocked()
	out, err := staged.decideLocked(tenantID, id, state, by, note, at)
	if err != nil {
		return rem.Proposal{}, err
	}
	if err := sink.Append(ctx, tenantID, event.Actor, event.Action, event.Target, auditData(event.Data, out)); err != nil {
		return rem.Proposal{}, err
	}
	m.publishLocked(staged)
	return out, nil
}

func (m *MemStore) cloneLocked() *MemStore {
	staged := NewMemStore()
	staged.seq = m.seq
	for tenantID, proposals := range m.all {
		staged.all[tenantID] = append([]rem.Proposal(nil), proposals...)
	}
	return staged
}

func (m *MemStore) publishLocked(staged *MemStore) {
	m.seq = staged.seq
	m.all = staged.all
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
