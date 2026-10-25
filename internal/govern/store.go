// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package govern

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/l7redact"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// The tenant_governance row shape (migration 0033; 0037 added ai_remote_egress)
// lives HERE, in core, as the single source of truth for both callers that
// touch it: the MSP/provider-plane store (ee/governance, cross-tenant via the
// provider role) and the per-tenant self-service management surface
// (PolicyStore below, tenant-scoped under RLS). Keeping the scan + upsert in one
// place means the two paths can never drift on columns or marshaling.

// ScanPolicy scans a tenant_governance row selected as
// (classifications, redact_from, redact_export, ai_remote_egress). ok=false with
// a nil error means no row exists (the deployment defaults apply).
func ScanPolicy(row pgx.Row) (Policy, bool, error) {
	var (
		classes  []byte
		from     string
		redactEx bool
		aiEgress bool
	)
	if err := row.Scan(&classes, &from, &redactEx, &aiEgress); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Policy{}, false, nil
		}
		return Policy{}, false, err
	}
	pol := Policy{RedactFrom: ParseClass(from), RedactExport: redactEx, AIRemoteEgress: aiEgress}
	if len(classes) > 0 {
		raw := map[string]string{}
		if err := json.Unmarshal(classes, &raw); err == nil && len(raw) > 0 {
			pol.Overrides = map[Category]Class{}
			for cat, cls := range raw {
				pol.Overrides[Category(cat)] = ParseClass(cls)
			}
		}
	}
	return pol, true, nil
}

// UpsertPolicyTx writes a tenant's governance policy row through q. It is
// parameterized on a tenancy.Querier so it runs in whatever transaction the
// caller opened — the provider-role transaction (ee/governance, cross-tenant)
// or the tenant-GUC-scoped maintenance transaction (PolicyStore.SetTenantPolicy).
// tenant_id is always the caller-supplied scope identity, never a request body
// value (docs/guardrails.md G7-1).
func UpsertPolicyTx(ctx context.Context, q tenancy.Querier, tenantID string, pol Policy, by string) error {
	classes := map[string]string{}
	for cat, cls := range pol.Overrides {
		classes[string(cat)] = cls.String()
	}
	classesJSON, err := json.Marshal(classes)
	if err != nil {
		return err
	}
	from := ""
	if pol.RedactFrom != ClassUnset {
		from = pol.RedactFrom.String()
	}
	_, err = q.Exec(ctx, `
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
}

// L7CaptureRedactionTx reads a tenant's L7 capture redaction floor statement
// through q ("" when no row or no statement exists; the caller applies the
// metadata default). q must already be scoped to tenantID (tenant GUC under
// RLS, or the provider role for a cross-tenant read).
func L7CaptureRedactionTx(ctx context.Context, q tenancy.Querier, tenantID string) (string, error) {
	var mode string
	err := q.QueryRow(ctx, `SELECT l7_capture_redaction FROM tenant_governance WHERE tenant_id = $1`, tenantID).Scan(&mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return mode, err
}

// EffectiveL7CaptureFloor turns a tenant's stored statement into the floor its
// agents and the ingest strip apply (D-43): no statement (or an unknown value)
// is the metadata default, and the regulated profile never allows anything
// looser than metadata, whatever the row says.
func EffectiveL7CaptureFloor(statement string, regulated bool) string {
	mode := l7redact.Normalize(statement)
	if !l7redact.ValidMode(mode) {
		mode = l7redact.DefaultMode
	}
	if regulated {
		mode = l7redact.Stricter(mode, l7redact.ModeMetadata)
	}
	return mode
}

// L7CaptureFloor reads the tenant's effective L7 capture redaction floor under
// the tenant's own RLS scope. A read error is returned; callers fail closed to
// the metadata default.
func (s *PolicyStore) L7CaptureFloor(ctx context.Context, tenantID string, regulated bool) (string, error) {
	var stmt string
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var e error
		stmt, e = L7CaptureRedactionTx(ctx, sc.Q, tenantID)
		return e
	})
	if err != nil {
		return l7redact.DefaultMode, err
	}
	return EffectiveL7CaptureFloor(stmt, regulated), nil
}

// TenantL7CaptureRedaction reads the tenant's stored L7 capture redaction
// statement ("" = none: the metadata default) under the tenant's RLS scope.
// It is the core surface's read (D-64): it works on every edition.
func (s *PolicyStore) TenantL7CaptureRedaction(ctx context.Context, tenantID string) (string, error) {
	var stmt string
	err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var e error
		stmt, e = L7CaptureRedactionTx(ctx, sc.Q, tenantID)
		return e
	})
	return stmt, err
}

// SetTenantL7CaptureRedaction writes the tenant's L7 capture redaction floor
// statement and appends the tamper-evident tenant audit receipt in ONE
// transaction (D-43, D-64: a core tenant setting, never license-gated). The
// row is provider-owned (0111 write fence), so the column is written under the
// provider role inside a tenant-GUC-bound maintenance transaction and the
// receipt appended as the tenant app role, exactly like SetTenantPolicy. Only
// this column is written; a missing receipt fails the write closed (G7-7).
//
// auditTx receives the statement the write replaces, read inside the same
// transaction under a row lock (and a per-tenant transaction lock for a tenant
// with no row yet), so concurrent updates each audit the value they actually
// replaced (RN3).
func (s *PolicyStore) SetTenantL7CaptureRedaction(ctx context.Context, tenantID, mode, by string, auditTx func(ctx context.Context, sc tenancy.Scope, prior string) error) error {
	if auditTx == nil {
		return ErrAuditReceiptRequired
	}
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	return tenancy.InTenantProviderMaintenance(tctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if sc.Tenant.String() != tenantID {
			return fmt.Errorf("govern: l7 policy tenant %q does not match transaction scope %q", tenantID, sc.Tenant)
		}
		prior, err := lockL7CaptureRedactionTx(ctx, sc.Q, tenantID)
		if err != nil {
			return err
		}
		if err := upsertL7CaptureRedactionTx(ctx, sc.Q, tenantID, mode, by); err != nil {
			return err
		}
		if _, err := sc.Q.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{tenancy.AppRole}.Sanitize()); err != nil {
			return fmt.Errorf("govern: assume app role for tenant audit receipt: %w", err)
		}
		return auditTx(ctx, sc, prior)
	})
}

// lockL7CaptureRedactionTx serializes this tenant's L7 policy writers and
// returns the current statement: a transaction-scoped advisory lock covers a
// tenant with no governance row yet (nothing to row-lock), and FOR UPDATE
// waits for any other writer of the row to commit before reading it.
func lockL7CaptureRedactionTx(ctx context.Context, q tenancy.Querier, tenantID string) (string, error) {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('l7_capture_redaction:'||$1::text, 0))`, tenantID); err != nil {
		return "", fmt.Errorf("govern: lock l7 policy: %w", err)
	}
	var mode string
	err := q.QueryRow(ctx, `SELECT l7_capture_redaction FROM tenant_governance WHERE tenant_id = $1 FOR UPDATE`, tenantID).Scan(&mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return mode, err
}

// upsertL7CaptureRedactionTx writes ONLY the L7 capture redaction column. It is
// separate from UpsertPolicyTx on purpose: the provider plane and the ee/
// governance surface call that one, and neither can change this value (D-43:
// the opt-in is the tenant's, audited on the tenant's chain; D-64: it is a
// core setting with its own core route, the single writer of this column).
func upsertL7CaptureRedactionTx(ctx context.Context, q tenancy.Querier, tenantID, mode, by string) error {
	_, err := q.Exec(ctx, `
		INSERT INTO tenant_governance (tenant_id, l7_capture_redaction, updated_at, updated_by)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id) DO UPDATE SET
			l7_capture_redaction = excluded.l7_capture_redaction,
			updated_at           = excluded.updated_at,
			updated_by           = excluded.updated_by`,
		tenantID, mode, time.Now().UTC(), by)
	return err
}

// ErrAuditReceiptRequired is returned when a policy write is attempted without
// a tenant audit receipt. A consent/governance change must never persist
// unaudited (docs/guardrails.md G7-7), so the write fails closed.
var ErrAuditReceiptRequired = errors.New("govern: a tenant audit receipt is required for a governance policy change")

// PolicyStore is the TENANT-scoped governance policy management store (core).
// It lets a tenant admin read and update their OWN tenant's governance policy —
// including the remote-AI egress consent (ai_remote_egress) — through the core
// /v1 API, instead of an operator hand-editing SQL. It is the self-service twin
// of the MSP/provider-plane ee/governance.Store: the provider store writes any
// tenant's row cross-tenant through the provider role; this store confines every
// read and write to the one tenant in context, at the storage layer.
//
// The classification + redaction MECHANISM and this policy row are core; the
// /v1 management SURFACE this store backs is unlocked only by the Enterprise
// `governance` license feature, gated at the main.go Build* attach seam
// (internal/license is the only feature→tier authority). It is a management
// surface for the EXISTING consent, not a relaxation: the AI egress gate
// (internal/ai) still fails closed and redacts regardless of who set the bit.
type PolicyStore struct{ pool *pgxpool.Pool }

// NewPolicyStore wraps the control-plane pool.
func NewPolicyStore(pool *pgxpool.Pool) *PolicyStore { return &PolicyStore{pool: pool} }

// TenantPolicy reads the calling tenant's governance policy. ok=false means no
// row is stored yet (the deployment defaults apply). The read runs as the tenant
// app role under RLS (the tenant_isolation policy on tenant_governance scopes it
// to the GUC-bound tenant), so a tenant can only ever read its own row — the
// same app-role read path the AI egress gate uses for ai_remote_egress.
func (s *PolicyStore) TenantPolicy(ctx context.Context, tenantID string) (Policy, bool, error) {
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	var (
		pol   Policy
		found bool
	)
	err := tenancy.InTenant(tctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var e error
		pol, found, e = ScanPolicy(sc.Q.QueryRow(ctx,
			`SELECT classifications, redact_from, redact_export, ai_remote_egress FROM tenant_governance WHERE tenant_id = $1`, tenantID))
		return e
	})
	return pol, found, err
}

// SetTenantPolicy upserts the calling tenant's governance policy and appends the
// tamper-evident tenant audit receipt in ONE transaction. The policy row is a
// provider-OWNED config table the tenant app role is deliberately write-fenced
// off (migration 0111 + the boot posture check), so the row is written under the
// provider role inside a tenant-GUC-bound maintenance transaction; the receipt
// is then appended after switching back to the tenant app role, because only the
// app role holds INSERT on the tenant's append-only audit chain (migration 0045)
// and the receipt must be the tenant's own. tenant_id is the caller scope,
// never a request body value (docs/guardrails.md G7-1); a missing receipt fails
// the whole write closed (G7-7).
func (s *PolicyStore) SetTenantPolicy(ctx context.Context, tenantID string, pol Policy, by string, auditTx func(context.Context, tenancy.Scope) error) error {
	if auditTx == nil {
		return ErrAuditReceiptRequired
	}
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenantID))
	return tenancy.InTenantProviderMaintenance(tctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		if sc.Tenant.String() != tenantID {
			return fmt.Errorf("govern: policy tenant %q does not match transaction scope %q", tenantID, sc.Tenant)
		}
		// Provider role: write the provider-owned policy row, scoped by the
		// caller's tenant identity (defense in depth above the bound GUC).
		if err := UpsertPolicyTx(ctx, sc.Q, tenantID, pol, by); err != nil {
			return err
		}
		// Tenant app role: the tamper-evident TENANT audit receipt. The GUC stays
		// bound across the role switch, so the append is RLS-scoped to this tenant.
		if _, err := sc.Q.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{tenancy.AppRole}.Sanitize()); err != nil {
			return fmt.Errorf("govern: assume app role for tenant audit receipt: %w", err)
		}
		return auditTx(ctx, sc)
	})
}
