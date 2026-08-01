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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	coreaudit "github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// PGStore is the production Store. Every query runs inside
// tenancy.InProvider — the probectl_provider role — so the provider plane's
// reach is bounded by that role's grants AT THE STORAGE LAYER: lifecycle
// tables, the provider audit chain, and SELECT over agents via the explicit
// fleet policy. It cannot read tests, results, or any telemetry table even
// if this code were buggy (defense-in-depth, guardrail 1).
type PGStore struct {
	pool *pgxpool.Pool
	q    tenancy.Querier // set only on the transaction-bound mutation facade
}

// NewPGStore wraps a pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

func (s *PGStore) in(ctx context.Context, fn func(context.Context, tenancy.Querier) error) error {
	if s.q != nil {
		return fn(ctx, s.q)
	}
	return tenancy.InProvider(ctx, s.pool, fn)
}

type transactionalAuditSink interface {
	AppendTx(context.Context, tenancy.Querier, string, string, string, map[string]any) error
	AppendBreakGlassTx(
		context.Context,
		tenancy.Querier,
		string,
		string,
		string,
		map[string]any,
		coreaudit.IRAttribution,
	) error
}

type boundProviderAudit struct {
	q    tenancy.Querier
	sink transactionalAuditSink
}

func (a boundProviderAudit) Append(ctx context.Context, actor, action, target string, data map[string]any) error {
	return a.sink.AppendTx(ctx, a.q, actor, action, target, data)
}

func (a boundProviderAudit) AppendBreakGlass(
	ctx context.Context,
	actor, action, target string,
	data map[string]any,
	attribution coreaudit.IRAttribution,
) error {
	return a.sink.AppendBreakGlassTx(
		ctx,
		a.q,
		actor,
		action,
		target,
		data,
		attribution,
	)
}

// WithAuditedMutation runs the provider write and audit-chain append inside the
// same provider-scoped transaction. The callback receives a facade bound to the
// current pgx transaction, so its Store methods cannot commit independently.
func (s *PGStore) WithAuditedMutation(ctx context.Context, sink AuditSink, fn AuditedMutation) error {
	txSink, ok := sink.(transactionalAuditSink)
	if !ok {
		return errors.New("provider: audit sink cannot join provider transaction")
	}
	return s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		return fn(ctx, &PGStore{q: q}, boundProviderAudit{q: q, sink: txSink})
	})
}

func mapPGErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// --- operators ---

const operatorCols = `id::text, email, name, role, status, password_hash <> '', created_at`

func scanOperator(row pgx.Row) (Operator, error) {
	var op Operator
	err := row.Scan(&op.ID, &op.Email, &op.Name, &op.Role, &op.Status, &op.Enrolled, &op.CreatedAt)
	return op, err
}

func insertOperator(
	ctx context.Context,
	q tenancy.Querier,
	op Operator,
	enrollTokenHash []byte,
) (Operator, error) {
	return scanOperator(q.QueryRow(ctx,
		`INSERT INTO provider_operators (email, name, role, status, enroll_token_hash)
		 VALUES ($1, $2, $3, 'disabled', $4) RETURNING `+operatorCols,
		op.Email, op.Name, op.Role, enrollTokenHash))
}

func (s *PGStore) CreateOperator(ctx context.Context, op Operator, enrollTokenHash []byte) (Operator, error) {
	var out Operator
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		out, e = insertOperator(ctx, q, op, enrollTokenHash)
		return e
	})
	return out, mapPGErr(err)
}

func (s *PGStore) BootstrapOperator(
	ctx context.Context,
	op Operator,
	enrollTokenHash []byte,
) (Operator, error) {
	var out Operator
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		// The provider operator roster is deployment-global, so one transaction
		// lock serializes the empty-roster predicate with the first insert.
		if _, err := q.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended('probectl:provider-bootstrap', 0))`); err != nil {
			return err
		}
		var exists bool
		if err := q.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM provider_operators)`).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		var err error
		out, err = insertOperator(ctx, q, op, enrollTokenHash)
		return err
	})
	return out, mapPGErr(err)
}

func (s *PGStore) OperatorByEmail(ctx context.Context, email string) (*Operator, *Credential, error) {
	var op Operator
	var cred Credential
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var keyID string
		var wrapped, ct []byte
		if err := q.QueryRow(ctx,
			`SELECT id::text, email, name, role, status, password_hash <> '', created_at,
			        password_hash, totp_key_id, totp_wrapped_dek, totp_ciphertext
			   FROM provider_operators WHERE lower(email) = lower($1)`, email).
			Scan(&op.ID, &op.Email, &op.Name, &op.Role, &op.Status, &op.Enrolled, &op.CreatedAt,
				&cred.PasswordHash, &keyID, &wrapped, &ct); err != nil {
			return err
		}
		cred.TOTP = crypto.Sealed{KeyID: keyID, WrappedDEK: wrapped, Ciphertext: ct}
		return nil
	})
	if err != nil {
		return nil, nil, mapPGErr(err)
	}
	return &op, &cred, nil
}

func (s *PGStore) OperatorByEnrollHash(ctx context.Context, hash []byte) (*Operator, error) {
	var op Operator
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		op, e = scanOperator(q.QueryRow(ctx,
			`SELECT `+operatorCols+` FROM provider_operators WHERE enroll_token_hash = $1`, hash))
		return e
	})
	if err != nil {
		return nil, mapPGErr(err)
	}
	return &op, nil
}

func (s *PGStore) SetOperatorTOTP(ctx context.Context, id string, sealed crypto.Sealed) error {
	return mapPGErr(s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		tag, err := q.Exec(ctx,
			`UPDATE provider_operators SET totp_key_id=$2, totp_wrapped_dek=$3, totp_ciphertext=$4, updated_at=now() WHERE id=$1`,
			id, sealed.KeyID, sealed.WrappedDEK, sealed.Ciphertext)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	}))
}

func (s *PGStore) ActivateOperator(ctx context.Context, id, passwordHash string) error {
	return mapPGErr(s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		tag, err := q.Exec(ctx,
			`UPDATE provider_operators SET password_hash=$2, status='active', enroll_token_hash=NULL, updated_at=now() WHERE id=$1`,
			id, passwordHash)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	}))
}

func (s *PGStore) SetOperatorStatus(ctx context.Context, id, status string) error {
	return mapPGErr(s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		tag, err := q.Exec(ctx,
			`UPDATE provider_operators SET status=$2, updated_at=now() WHERE id=$1`, id, status)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	}))
}

func (s *PGStore) ListOperators(ctx context.Context) ([]Operator, error) {
	var out []Operator
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `SELECT `+operatorCols+` FROM provider_operators ORDER BY email`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			op, err := scanOperator(rows)
			if err != nil {
				return err
			}
			out = append(out, op)
		}
		return rows.Err()
	})
	return out, mapPGErr(err)
}

func (s *PGStore) CountOperators(ctx context.Context) (int, error) {
	var n int
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		return q.QueryRow(ctx, `SELECT count(*) FROM provider_operators`).Scan(&n)
	})
	return n, mapPGErr(err)
}

// --- tenants ---

const tenantCols = `id::text, slug, name, status, isolation_model, residency, created_at`
const tenantProvisionCols = `id::text, slug, name, 'provisioning'::text, isolation_model, residency, created_at`

func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.IsolationModel, &t.Residency, &t.CreatedAt)
	return t, err
}

func lockTenantBand(ctx context.Context, q tenancy.Querier) error {
	_, err := q.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended('probectl:tenant-band', 0))`)
	return err
}

func enforceTenantBand(ctx context.Context, q tenancy.Querier, tenantBand int) error {
	if tenantBand <= 0 {
		return nil
	}
	var active int
	if err := q.QueryRow(ctx,
		`SELECT count(*) FROM tenants WHERE status IN ('active','suspended')`).Scan(&active); err != nil {
		return err
	}
	if active >= tenantBand {
		return ErrBandExhausted
	}
	return nil
}

func (s *PGStore) CreateTenant(
	ctx context.Context,
	slug, name, isolationModel, residency string,
	tenantBand int,
) (Tenant, error) {
	if isolationModel == "" {
		isolationModel = "pooled"
	}
	if isolationModel != "pooled" {
		return Tenant{}, errors.New("provider: isolated tenants must use resumable provisioning")
	}
	var out Tenant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		if err := lockTenantBand(ctx, q); err != nil {
			return err
		}
		if err := enforceTenantBand(ctx, q, tenantBand); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, slug); err != nil {
			return err
		}
		var pending bool
		if err := q.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM tenant_provisioning WHERE slug = $1)`, slug).Scan(&pending); err != nil {
			return err
		}
		if pending {
			return ErrConflict
		}
		var e error
		out, e = scanTenant(q.QueryRow(ctx,
			`INSERT INTO tenants (slug, name, isolation_model, residency) VALUES ($1, $2, $3, $4) RETURNING `+tenantCols,
			slug, name, isolationModel, residency))
		return e
	})
	return out, mapPGErr(err)
}

func (s *PGStore) CreateTenantProvision(
	ctx context.Context,
	slug, name, isolationModel, residency string,
) (Tenant, error) {
	if isolationModel != "siloed" && isolationModel != "hybrid" {
		return Tenant{}, errors.New("provider: resumable provisioning requires siloed or hybrid isolation")
	}
	var out Tenant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, slug); err != nil {
			return err
		}
		var exists bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tenants WHERE slug = $1)`, slug).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return ErrConflict
		}
		var err error
		out, err = scanTenant(q.QueryRow(ctx,
			`INSERT INTO tenant_provisioning (slug, name, isolation_model, residency)
			 VALUES ($1, $2, $3, $4) RETURNING `+tenantProvisionCols,
			slug, name, isolationModel, residency))
		return err
	})
	return out, mapPGErr(err)
}

func (s *PGStore) CompleteTenantProvision(
	ctx context.Context,
	id string,
	tenantBand int,
) (Tenant, bool, error) {
	var out Tenant
	completed := false
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		if err := lockTenantBand(ctx, q); err != nil {
			return err
		}
		pending, err := scanTenant(q.QueryRow(ctx,
			`SELECT `+tenantProvisionCols+` FROM tenant_provisioning WHERE id = $1`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			out, err = scanTenant(q.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id = $1`, id))
			if err == nil && out.Status != "active" {
				return ErrConflict
			}
			return err
		}
		if err != nil {
			return err
		}
		if err := enforceTenantBand(ctx, q, tenantBand); err != nil {
			return err
		}
		if _, err := q.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, pending.Slug); err != nil {
			return err
		}
		out, err = scanTenant(q.QueryRow(ctx,
			`INSERT INTO tenants (id, slug, name, status, isolation_model, residency, created_at, updated_at)
			 VALUES ($1, $2, $3, 'active', $4, $5, $6, now())
			 RETURNING `+tenantCols,
			pending.ID, pending.Slug, pending.Name, pending.IsolationModel, pending.Residency, pending.CreatedAt))
		if err != nil {
			return err
		}
		if tag, err := q.Exec(ctx, `DELETE FROM tenant_provisioning WHERE id = $1`, id); err != nil {
			return err
		} else if tag.RowsAffected() != 1 {
			return ErrConflict
		}
		completed = true
		return nil
	})
	if err != nil {
		return Tenant{}, false, mapPGErr(err)
	}
	return out, completed, nil
}

func (s *PGStore) RenameTenant(ctx context.Context, id, name string) (Tenant, error) {
	var out Tenant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		out, e = scanTenant(q.QueryRow(ctx,
			`UPDATE tenants SET name=$2, updated_at=now() WHERE id=$1 RETURNING `+tenantCols, id, name))
		return e
	})
	return out, mapPGErr(err)
}

func (s *PGStore) SetTenantStatus(ctx context.Context, id, status string) (Tenant, error) {
	var out Tenant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		out, e = scanTenant(q.QueryRow(ctx,
			`UPDATE tenants SET status=$2, updated_at=now() WHERE id=$1 RETURNING `+tenantCols, id, status))
		return e
	})
	return out, mapPGErr(err)
}

func (s *PGStore) ListTenants(ctx context.Context) ([]Tenant, error) {
	var out []Tenant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `
			SELECT id::text, slug, name, status, isolation_model, residency, created_at
			  FROM tenants
			UNION ALL
			SELECT id::text, slug, name, 'provisioning', isolation_model, residency, created_at
			  FROM tenant_provisioning
			 ORDER BY slug`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanTenant(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, mapPGErr(err)
}

func (s *PGStore) TenantBySlug(ctx context.Context, slug string) (*Tenant, error) {
	var out Tenant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var err error
		out, err = scanTenant(q.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE slug = $1`, slug))
		if errors.Is(err, pgx.ErrNoRows) {
			out, err = scanTenant(q.QueryRow(ctx,
				`SELECT `+tenantProvisionCols+` FROM tenant_provisioning WHERE slug = $1`, slug))
		}
		return err
	})
	if err != nil {
		return nil, mapPGErr(err)
	}
	return &out, nil
}

func (s *PGStore) CountActiveTenants(ctx context.Context) (int, error) {
	var n int
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		// Suspended tenants still occupy a licensed band slot; offboarded do not.
		return q.QueryRow(ctx,
			`SELECT count(*) FROM tenants WHERE status IN ('active','suspended')`).Scan(&n)
	})
	return n, mapPGErr(err)
}

// --- fleet (the sanctioned cross-tenant read: counts/versions only) ---

func (s *PGStore) FleetSummary(ctx context.Context) ([]TenantFleet, error) {
	var out []TenantFleet
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		// Reads the AGGREGATE-ONLY fleet view (migration 0088), not agents:
		// the provider role holds no row-read capability on tenant-owned agent
		// rows, so this query cannot be widened into one (S-1612260f).
		rows, err := q.Query(ctx, `
			SELECT t.id::text, t.slug, t.name, t.status,
			       coalesce(c.agents_total, 0),
			       coalesce(c.agents_online, 0),
			       coalesce(c.agents_stale, 0)
			  FROM tenants t
			  LEFT JOIN provider_agent_fleet_counts c ON c.tenant_id = t.id
			 ORDER BY t.slug`)
		if err != nil {
			return err
		}
		idx := map[string]int{}
		for rows.Next() {
			var f TenantFleet
			if err := rows.Scan(&f.TenantID, &f.TenantSlug, &f.TenantName, &f.TenantStatus,
				&f.AgentsTotal, &f.AgentsOnline, &f.AgentsStale); err != nil {
				rows.Close()
				return err
			}
			f.Versions = map[string]int{}
			idx[f.TenantID] = len(out)
			out = append(out, f)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		vrows, err := q.Query(ctx, `
			SELECT tenant_id::text, agent_version, agents
			  FROM provider_agent_fleet_versions`)
		if err != nil {
			return err
		}
		defer vrows.Close()
		for vrows.Next() {
			var tid, ver string
			var n int
			if err := vrows.Scan(&tid, &ver, &n); err != nil {
				return err
			}
			if i, ok := idx[tid]; ok {
				out[i].Versions[ver] = n
			}
		}
		return vrows.Err()
	})
	return out, mapPGErr(err)
}

// --- break-glass grants ---

const grantCols = `g.id::text, g.operator_id::text, o.email, g.tenant_id::text, g.reason, g.scope,
	g.granted_by, g.granted_at, g.expires_at,
	coalesce(g.consented_by,''), g.consented_at, coalesce(g.denied_by,''), g.denied_at,
	coalesce(g.revoked_by,''), g.revoked_at, g.use_count`

func scanGrant(row pgx.Row) (Grant, error) {
	var g Grant
	err := row.Scan(&g.ID, &g.OperatorID, &g.OperatorEmail, &g.TenantID, &g.Reason, &g.Scope,
		&g.GrantedBy, &g.GrantedAt, &g.ExpiresAt,
		&g.ConsentedBy, &g.ConsentedAt, &g.DeniedBy, &g.DeniedAt,
		&g.RevokedBy, &g.RevokedAt, &g.UseCount)
	return g, err
}

const grantFrom = ` FROM break_glass_grants g JOIN provider_operators o ON o.id = g.operator_id `

func (s *PGStore) CreateGrant(ctx context.Context, g Grant) (Grant, error) {
	var out Grant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var id string
		if err := q.QueryRow(ctx,
			`INSERT INTO break_glass_grants (operator_id, tenant_id, reason, scope, granted_by, granted_at, expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id::text`,
			g.OperatorID, g.TenantID, g.Reason, g.Scope, g.GrantedBy, g.GrantedAt, g.ExpiresAt).Scan(&id); err != nil {
			return err
		}
		var e error
		out, e = scanGrant(q.QueryRow(ctx, `SELECT `+grantCols+grantFrom+`WHERE g.id = $1`, id))
		return e
	})
	return out, mapPGErr(err)
}

func (s *PGStore) GetGrant(ctx context.Context, id string) (*Grant, error) {
	var g Grant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		g, e = scanGrant(q.QueryRow(ctx, `SELECT `+grantCols+grantFrom+`WHERE g.id = $1`, id))
		return e
	})
	if err != nil {
		return nil, mapPGErr(err)
	}
	return &g, nil
}

func (s *PGStore) listGrants(ctx context.Context, where string, args ...any) ([]Grant, error) {
	var out []Grant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		rows, err := q.Query(ctx, `SELECT `+grantCols+grantFrom+where+` ORDER BY g.granted_at DESC`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			g, err := scanGrant(rows)
			if err != nil {
				return err
			}
			out = append(out, g)
		}
		return rows.Err()
	})
	return out, mapPGErr(err)
}

func (s *PGStore) ListGrants(ctx context.Context) ([]Grant, error) {
	return s.listGrants(ctx, "")
}

func (s *PGStore) ListGrantsForTenant(ctx context.Context, tenantID string) ([]Grant, error) {
	return s.listGrants(ctx, `WHERE g.tenant_id = $1`, tenantID)
}

// decideGrant is the ONE state-transition primitive for break-glass consent,
// deny and revoke (Foundation-Loop S-ae06d833). Every transition now does what
// UseGrant always did: take the row lock, re-read the state INSIDE the
// transaction, and re-state the precondition as UPDATE predicates so a lost
// race fails closed at the storage layer instead of relying on the ordering of
// cases in a Go switch. setSQL assigns the decision columns; guardSQL is the
// extra precondition that transition requires beyond "still pending".
func (s *PGStore) decideGrant(ctx context.Context, id, setSQL, guardSQL string, by string, at time.Time) (*Grant, error) {
	var g Grant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var err error
		g, err = scanGrant(q.QueryRow(ctx,
			`SELECT `+grantCols+grantFrom+`WHERE g.id = $1 FOR UPDATE OF g`, id))
		if err != nil {
			return err
		}
		tag, err := q.Exec(ctx,
			`UPDATE break_glass_grants SET `+setSQL+` WHERE id = $1 `+guardSQL, id, by, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			// Another transaction decided this grant first. Fail closed: the
			// caller sees the conflict rather than a silently clobbered state.
			return ErrGrantDecided
		}
		g, err = scanGrant(q.QueryRow(ctx, `SELECT `+grantCols+grantFrom+`WHERE g.id = $1`, id))
		return err
	})
	if err != nil {
		return nil, mapPGErr(err)
	}
	return &g, nil
}

// pendingGuard is the "still undecided" precondition shared by consent and
// deny: no prior decision of any kind, and not yet expired.
const pendingGuard = `AND consented_at IS NULL AND denied_at IS NULL AND revoked_at IS NULL AND expires_at > $3`

func (s *PGStore) ConsentGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error) {
	return s.decideGrant(ctx, id, `consented_by=$2, consented_at=$3`, pendingGuard, by, at)
}

func (s *PGStore) DenyGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error) {
	return s.decideGrant(ctx, id, `denied_by=$2, denied_at=$3`, pendingGuard, by, at)
}

// RevokeGrant may follow a consent (revoking an active grant is the point) but
// never a deny or a second revoke, and never resurrects an expired grant.
func (s *PGStore) RevokeGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error) {
	return s.decideGrant(ctx, id, `revoked_by=$2, revoked_at=$3`,
		`AND denied_at IS NULL AND revoked_at IS NULL AND expires_at > $3`, by, at)
}

// UseGrant is the grant access linearization point. The row lock keeps revoke
// and use mutually ordered, while the repeated UPDATE predicates make the
// fail-closed contract explicit at the storage layer.
func (s *PGStore) UseGrant(ctx context.Context, id, operatorID string, at time.Time) (*Grant, error) {
	var g Grant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var err error
		g, err = scanGrant(q.QueryRow(ctx,
			`SELECT `+grantCols+grantFrom+`WHERE g.id = $1 FOR UPDATE OF g`, id))
		if err != nil {
			return err
		}
		if g.OperatorID != operatorID {
			return ErrNotGrantee
		}
		if !g.Usable(at) {
			return fmt.Errorf("%w (state: %s)", ErrNotConsented, g.State(at))
		}
		tag, err := q.Exec(ctx,
			`UPDATE break_glass_grants
			    SET use_count = use_count + 1
			  WHERE id = $1
			    AND operator_id = $2
			    AND consented_at IS NOT NULL
			    AND denied_at IS NULL
			    AND revoked_at IS NULL
			    AND expires_at > $3`,
			id, operatorID, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return ErrNotConsented
		}
		g.UseCount++
		return nil
	})
	if err != nil {
		return nil, mapPGErr(err)
	}
	return &g, nil
}
