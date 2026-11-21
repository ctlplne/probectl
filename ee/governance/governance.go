// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

// Package governance is the ee/ data-governance layer (S-EE3, F34, unlocked by
// the `governance` Enterprise feature). The classification + redaction
// MECHANISM is core (internal/govern); this package adds the per-tenant POLICY
// store and the operator surface, and composes the already-shipped slices into
// one governance view: classification + redaction (S-EE3) + retention (S-T5) +
// residency (S-T2/S-EE2) + BYOK / no-downtime rotation (S-T6).
package governance

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/govern"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// Store persists per-tenant governance policies (tenant_governance, migration
// 0033) via the provider role — governance is control-plane policy the
// redaction seam consults for every tenant; writes come from the provider
// plane. The tenant_governance row shape (scan + upsert) lives in core
// (internal/govern.ScanPolicy / UpsertPolicyTx) so the provider-plane path here
// and the tenant self-service path (govern.PolicyStore) can never drift.
type Store struct{ pool *pgxpool.Pool }

// NewStore wraps a pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// PolicyFor implements govern.PolicySource: the per-tenant policy, or ok=false
// when none is stored (defaults apply).
func (s *Store) PolicyFor(ctx context.Context, tenantID string) (govern.Policy, bool, error) {
	var (
		pol   govern.Policy
		found bool
	)
	err := tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		var e error
		pol, found, e = govern.ScanPolicy(q.QueryRow(ctx,
			`SELECT classifications, redact_from, redact_export, ai_remote_egress FROM tenant_governance WHERE tenant_id = $1`, tenantID))
		return e
	})
	return pol, found, err
}

// Upsert stores a tenant's governance policy (the provider tuning surface).
func (s *Store) Upsert(ctx context.Context, tenantID string, pol govern.Policy, by string) error {
	return tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		return govern.UpsertPolicyTx(ctx, q, tenantID, pol, by)
	})
}

// ChangeAudited reads the current policy under the same row lock as its
// replacement. Both the policy change and its audit append commit together.
func (s *Store) ChangeAudited(ctx context.Context, tenantID, by string,
	change func(govern.Policy) (govern.Policy, error),
	auditTx func(context.Context, tenancy.Querier, govern.Policy, bool, govern.Policy) error,
) error {
	if auditTx == nil {
		return govern.ErrAuditReceiptRequired
	}
	return tenancy.InProvider(ctx, s.pool, func(ctx context.Context, q tenancy.Querier) error {
		// A first edit must also serialize with a tenant's first policy
		// write. A provisional default row is invisible until commit.
		result, err := q.Exec(ctx, `
			INSERT INTO tenant_governance (tenant_id) VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID)
		if err != nil {
			return err
		}
		var prior govern.Policy
		priorFound := result.RowsAffected() == 0
		if priorFound {
			var exists bool
			prior, exists, err = govern.ScanPolicy(q.QueryRow(ctx, `
				SELECT classifications, redact_from, redact_export, ai_remote_egress
				  FROM tenant_governance WHERE tenant_id = $1 FOR UPDATE`, tenantID))
			if err != nil {
				return err
			}
			if !exists {
				return pgx.ErrNoRows
			}
		}
		next, err := change(prior)
		if err != nil {
			return err
		}
		if err := govern.UpsertPolicyTx(ctx, q, tenantID, next, by); err != nil {
			return err
		}
		return auditTx(ctx, q, prior, priorFound, next)
	})
}
