// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tenantlife

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestAUD04ProviderCannotMutateTenantAuditTrail (live Postgres) locks in the
// AUD-04 fix: the tenant audit trail is no longer mutable through a
// caller-settable probectl.tenant_id GUC.
//
//   - As probectl_provider with an ARBITRARY tenant GUC set by the role itself,
//     SELECT and DELETE on audit_events and UPDATE on audit_stream_heads all
//     fail permission-denied (SQLSTATE 42501) — the GUC is not an authority.
//   - As probectl_app, UPDATE on audit_stream_heads is likewise denied; the app
//     stays append-only and cannot rewind a head.
//   - The legitimate retention prune still works, now through the SECURITY
//     DEFINER prefix function: it removes ONLY the victim's exported prefix,
//     leaves a bystander tenant's chain intact, and both chains still verify.
func TestAUD04ProviderCannotMutateTenantAuditTrail(t *testing.T) {
	pool := itPool(t)
	defer pool.Close()
	ctx := context.Background()

	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	victim := mkTenant(t, pool, "it-aud04-victim-"+stamp)
	bystander := mkTenant(t, pool, "it-aud04-bystander-"+stamp)

	appendN := func(tenantID string, n int) {
		t.Helper()
		if err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				for i := 0; i < n; i++ {
					if _, err := audit.TenantAppend(
						ctx, sc, "aud04", "seed", fmt.Sprintf("e%d", i), map[string]any{},
					); err != nil {
						return err
					}
				}
				return nil
			},
		); err != nil {
			t.Fatalf("seed audit chain for %s: %v", tenantID, err)
		}
	}
	appendN(victim, 4)
	appendN(bystander, 3)

	// Mark the victim's first two events durably exported, so the retention
	// prune below (watermark 2) has a consistent SIEM cursor to reconcile its
	// receipt append against.
	if err := tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(victim)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			return (store.SIEMDelivery{}).Advance(ctx, sc, 2)
		},
	); err != nil {
		t.Fatalf("advance victim SIEM cursor: %v", err)
	}

	denied := func(err error) bool {
		var pgErr *pgconn.PgError
		return errors.As(err, &pgErr) && pgErr.Code == "42501"
	}

	// (a) Provider self-sets the victim's GUC — the attack in the finding — and
	//     is still refused every direct mutation path. Each probe runs in its
	//     own transaction because a permission error aborts the transaction.
	providerProbe := func(sql string) error {
		return tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
			if _, err := q.Exec(
				ctx, `SELECT set_config('probectl.tenant_id', $1, true)`, victim,
			); err != nil {
				return err
			}
			_, err := q.Exec(ctx, sql, victim)
			return err
		})
	}

	// SELECT must be denied at the grant layer (not merely return zero rows).
	selErr := tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
		if _, err := q.Exec(
			ctx, `SELECT set_config('probectl.tenant_id', $1, true)`, victim,
		); err != nil {
			return err
		}
		var n int64
		return q.QueryRow(
			ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid`, victim,
		).Scan(&n)
	})
	if !denied(selErr) {
		t.Fatalf("provider SELECT audit_events (GUC=victim) = %v, want permission denied (42501)", selErr)
	}

	if err := providerProbe(
		`DELETE FROM audit_events WHERE tenant_id = $1::uuid`,
	); !denied(err) {
		t.Fatalf("provider DELETE audit_events (GUC=victim) = %v, want permission denied (42501)", err)
	}
	if err := providerProbe(
		`UPDATE audit_stream_heads SET head_seq = 0, head_hash = '' WHERE tenant_id = $1::uuid`,
	); !denied(err) {
		t.Fatalf("provider UPDATE audit_stream_heads (GUC=victim) = %v, want permission denied (42501)", err)
	}

	// (b) The app role cannot UPDATE audit_stream_heads either (append-only; head
	//     advancement is now only through the monotonic SECURITY DEFINER path).
	appErr := tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(victim)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(
				ctx,
				`UPDATE audit_stream_heads SET head_seq = 0, head_hash = '' WHERE tenant_id = $1::uuid`,
				victim,
			)
			return err
		},
	)
	if !denied(appErr) {
		t.Fatalf("app UPDATE audit_stream_heads = %v, want permission denied (42501)", appErr)
	}

	// Tenant audit rows are untouched by the refused mutations.
	if got := auditEventCount(t, pool, victim); got != 4 {
		t.Fatalf("victim audit rows after refused mutations = %d, want 4", got)
	}

	// (c) Legitimate retention through the new SECURITY DEFINER prefix function.
	//     now is set an hour ahead with a 30-minute window so the whole stream is
	//     age-eligible; the watermark of 2 bounds the delete to the exported
	//     prefix (seq 1..2), proving prefix-only deletion — the tail survives.
	now := time.Now().UTC().Add(time.Hour)
	pruned, err := audit.PruneTenant(
		ctx, pool, victim, audit.RetentionPolicy{Window: 30 * time.Minute}, 2, now,
	)
	if err != nil || pruned != 2 {
		t.Fatalf("legitimate prune of victim = (%d, %v), want (2, nil)", pruned, err)
	}

	if seqPresent(t, pool, victim, 1) || seqPresent(t, pool, victim, 2) {
		t.Fatalf("victim exported prefix seq 1..2 should be pruned")
	}
	if !seqPresent(t, pool, victim, 3) || !seqPresent(t, pool, victim, 4) {
		t.Fatalf("victim retained tail seq 3..4 must survive the prefix prune")
	}
	if got := auditEventCount(t, pool, bystander); got != 3 {
		t.Fatalf("bystander audit rows after victim prune = %d, want 3 (isolation)", got)
	}

	verify := func(tenantID string) error {
		return tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			audit.TenantVerify,
		)
	}
	if err := verify(victim); err != nil {
		t.Fatalf("victim hash chain must still verify after the prefix prune: %v", err)
	}
	if err := verify(bystander); err != nil {
		t.Fatalf("bystander hash chain must verify: %v", err)
	}
}

func auditEventCount(t *testing.T, pool *pgxpool.Pool, tenantID string) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(
		context.Background(),
		`SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&n); err != nil {
		t.Fatalf("count audit_events for %s: %v", tenantID, err)
	}
	return n
}

func seqPresent(t *testing.T, pool *pgxpool.Pool, tenantID string, seq int64) bool {
	t.Helper()
	var n int64
	if err := pool.QueryRow(
		context.Background(),
		`SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid AND seq = $2`,
		tenantID,
		seq,
	).Scan(&n); err != nil {
		t.Fatalf("probe audit_events seq %d for %s: %v", seq, tenantID, err)
	}
	return n > 0
}
