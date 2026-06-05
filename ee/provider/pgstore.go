// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).
// See ee/doc.go for the boundary rules every ee/ file observes.

package provider

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// PGStore is the production Store. Every query runs inside
// tenancy.InProvider — the probectl_provider role — so the provider plane's
// reach is bounded by that role's grants AT THE STORAGE LAYER: lifecycle
// tables, the provider audit chain, and SELECT over agents via the explicit
// fleet policy. It cannot read tests, results, or any telemetry table even
// if this code were buggy (defense-in-depth, guardrail 1).
type PGStore struct{ pool *pgxpool.Pool }

// NewPGStore wraps a pool.
func NewPGStore(pool *pgxpool.Pool) *PGStore { return &PGStore{pool: pool} }

func (s *PGStore) in(ctx context.Context, fn func(context.Context, tenancy.Querier) error) error {
	return tenancy.InProvider(ctx, s.pool, fn)
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

func (s *PGStore) CreateOperator(ctx context.Context, op Operator, enrollTokenHash []byte) (Operator, error) {
	var out Operator
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		out, e = scanOperator(q.QueryRow(ctx,
			`INSERT INTO provider_operators (email, name, role, status, enroll_token_hash)
			 VALUES ($1, $2, $3, 'disabled', $4) RETURNING `+operatorCols,
			op.Email, op.Name, op.Role, enrollTokenHash))
		return e
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

func scanTenant(row pgx.Row) (Tenant, error) {
	var t Tenant
	err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.IsolationModel, &t.Residency, &t.CreatedAt)
	return t, err
}

func (s *PGStore) CreateTenant(ctx context.Context, slug, name, isolationModel, residency string) (Tenant, error) {
	if isolationModel == "" {
		isolationModel = "pooled"
	}
	var out Tenant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		out, e = scanTenant(q.QueryRow(ctx,
			`INSERT INTO tenants (slug, name, isolation_model, residency) VALUES ($1, $2, $3, $4) RETURNING `+tenantCols,
			slug, name, isolationModel, residency))
		return e
	})
	return out, mapPGErr(err)
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
		rows, err := q.Query(ctx, `SELECT `+tenantCols+` FROM tenants ORDER BY slug`)
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
		rows, err := q.Query(ctx, `
			SELECT t.id::text, t.slug, t.name, t.status,
			       count(a.id),
			       count(a.id) FILTER (WHERE a.status = 'online'),
			       count(a.id) FILTER (WHERE a.status = 'online' AND a.last_seen_at < now() - interval '5 minutes')
			  FROM tenants t
			  LEFT JOIN agents a ON a.tenant_id = t.id
			 GROUP BY t.id, t.slug, t.name, t.status
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
			SELECT tenant_id::text, agent_version, count(*)
			  FROM agents WHERE agent_version <> ''
			 GROUP BY tenant_id, agent_version`)
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

func (s *PGStore) grantUpdate(ctx context.Context, id, sql string, args ...any) (*Grant, error) {
	var g Grant
	err := s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		tag, err := q.Exec(ctx, sql, args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		var e error
		g, e = scanGrant(q.QueryRow(ctx, `SELECT `+grantCols+grantFrom+`WHERE g.id = $1`, id))
		return e
	})
	if err != nil {
		return nil, mapPGErr(err)
	}
	return &g, nil
}

func (s *PGStore) ConsentGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error) {
	return s.grantUpdate(ctx, id,
		`UPDATE break_glass_grants SET consented_by=$2, consented_at=$3 WHERE id=$1`, id, by, at)
}

func (s *PGStore) DenyGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error) {
	return s.grantUpdate(ctx, id,
		`UPDATE break_glass_grants SET denied_by=$2, denied_at=$3 WHERE id=$1`, id, by, at)
}

func (s *PGStore) RevokeGrant(ctx context.Context, id, by string, at time.Time) (*Grant, error) {
	return s.grantUpdate(ctx, id,
		`UPDATE break_glass_grants SET revoked_by=$2, revoked_at=$3 WHERE id=$1`, id, by, at)
}

func (s *PGStore) IncrementGrantUse(ctx context.Context, id string) error {
	return mapPGErr(s.in(ctx, func(ctx context.Context, q tenancy.Querier) error {
		tag, err := q.Exec(ctx, `UPDATE break_glass_grants SET use_count = use_count + 1 WHERE id=$1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	}))
}
