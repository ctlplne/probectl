// probectl Commercial License — PLACEHOLDER (legal text TBD with counsel).

// Package governance is the ee/ data-governance layer (S-EE3, F34, unlocked by
// the `governance` Enterprise feature). The classification + redaction
// MECHANISM is core (internal/govern); this package adds the per-tenant POLICY
// store and the operator surface, and composes the already-shipped slices into
// one governance view: classification + redaction (S-EE3) + retention (S-T5) +
// residency (S-T2/S-EE2) + BYOK / no-downtime rotation (S-T6).
package governance

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/govern"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// Store persists per-tenant governance policies (tenant_governance, migration
// 0033) via the provider role — governance is control-plane policy the
// redaction seam consults for every tenant; writes come from the provider
// plane.
type Store struct{ pool *pgxpool.Pool }

// NewStore wraps a pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

func scanPolicy(row pgx.Row) (govern.Policy, bool, error) {
	var (
		classes  []byte
		from     string
		redactEx bool
		aiEgress bool
	)
	if err := row.Scan(&classes, &from, &redactEx, &aiEgress); err != nil {
		if err == pgx.ErrNoRows {
			return govern.Policy{}, false, nil
		}
		return govern.Policy{}, false, err
	}
	pol := govern.Policy{RedactFrom: govern.ParseClass(from), RedactExport: redactEx, AIRemoteEgress: aiEgress}
	if len(classes) > 0 {
		raw := map[string]string{}
		if err := json.Unmarshal(classes, &raw); err == nil && len(raw) > 0 {
			pol.Overrides = map[govern.Category]govern.Class{}
			for cat, cls := range raw {
				pol.Overrides[govern.Category(cat)] = govern.ParseClass(cls)
			}
		}
	}
	return pol, true, nil
}

// PolicyFor implements govern.PolicySource: the per-tenant policy, or ok=false
// when none is stored (defaults apply).
func (s *Store) PolicyFor(ctx context.Context, tenantID string) (govern.Policy, bool, error) {
	var (
		pol   govern.Policy
		found bool
	)
	err := tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		pol, found, e = scanPolicy(q.QueryRow(ctx,
			`SELECT classifications, redact_from, redact_export, ai_remote_egress FROM tenant_governance WHERE tenant_id = $1`, tenantID))
		return e
	})
	return pol, found, err
}

// Upsert stores a tenant's governance policy (the provider tuning surface).
func (s *Store) Upsert(ctx context.Context, tenantID string, pol govern.Policy, by string) error {
	classes := map[string]string{}
	for cat, cls := range pol.Overrides {
		classes[string(cat)] = cls.String()
	}
	classesJSON, err := json.Marshal(classes)
	if err != nil {
		return err
	}
	from := ""
	if pol.RedactFrom != govern.ClassUnset {
		from = pol.RedactFrom.String()
	}
	return tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		_, err := q.Exec(ctx, `
			INSERT INTO tenant_governance (tenant_id, classifications, redact_from, redact_export, ai_remote_egress, updated_at, updated_by)
			VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7)
			ON CONFLICT (tenant_id) DO UPDATE SET
				classifications  = excluded.classifications,
				redact_from      = excluded.redact_from,
				redact_export    = excluded.redact_export,
				ai_remote_egress = excluded.ai_remote_egress,
				updated_at       = excluded.updated_at,
				updated_by       = excluded.updated_by`,
			tenantID, string(classesJSON), from, pol.RedactExport, pol.AIRemoteEgress, time.Now().UTC(), by)
		return err
	})
}
