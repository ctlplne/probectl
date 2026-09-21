// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestProviderRetentionPrune drives the EXC-ORG-01 retention pruner against real
// Postgres: append a run of ordinary provider events, then prune with a
// watermark + window and assert (a) only events BOTH old enough AND at/under the
// exported watermark are removed, (b) newer or un-exported events survive, and
// (c) the remaining chain STILL VERIFIES (no gap broke the hash chain a verifier
// walks). This is the regulated-profile counterpart to the append-only WORM
// export: history is retained for the window, then pruned safely.
func TestProviderRetentionPrune(t *testing.T) {
	ctx := context.Background()
	admin := setup(ctx, t)
	defer admin.Close()
	pool := isolatedProviderRetentionPool(t, admin)
	defer pool.Close()

	base, err := ProviderHeadSeq(ctx, pool)
	if err != nil {
		t.Fatalf("head seq: %v", err)
	}
	if base != 0 {
		t.Fatalf("isolated provider audit stream starts at seq %d, want 0", base)
	}

	// Append 6 events on the provider chain.
	const n = 6
	for i := 0; i < n; i++ {
		if _, err := ProviderAppend(ctx, pool, "operator-x", "retention.seed",
			fmt.Sprintf("ret-%d", i), map[string]any{"i": i}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	// Age the FIRST 4 of our appended rows past the retention window so they are
	// age-eligible; the last 2 stay recent. (We backdate created_at directly —
	// this is the maintenance/owner path the pruner itself uses.)
	old := time.Now().Add(-48 * time.Hour)
	if _, err := pool.Exec(ctx,
		`UPDATE provider_audit_events SET created_at = $1 WHERE seq > $2 AND seq <= $3`,
		old, base, base+4); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	policy := RetentionPolicy{Window: 24 * time.Hour}

	// Watermark covers only the first 3 of the 4 aged rows: row 4 is aged but NOT
	// yet exported, so it must be KEPT (fail closed on un-exported history).
	watermark := base + 3
	pruned, err := pruneProviderWithProof(
		ctx,
		pool,
		policy,
		verifiedWORMOnlyProof(watermark),
		time.Now(),
	)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if pruned != 3 {
		t.Fatalf("pruned %d rows, want exactly 3 (aged AND exported)", pruned)
	}

	// Pruning a contiguous PREFIX is expected to break a naive verify across the
	// prune boundary (seq base+4's prev_hash points at the now-deleted base+3 —
	// that history lives on only in the signed WORM segments). What must hold is
	// that the KEPT SUFFIX is internally consistent: anchor on the first kept row
	// (base+4) and verify the rest of the chain links cleanly. No interior gap was
	// introduced among the kept rows.
	firstKept := base + 4
	if err := ProviderVerifyFrom(ctx, pool, firstKept); err != nil {
		t.Fatalf("kept provider suffix must still verify after prune: %v", err)
	}
	// And the aged-but-UN-exported row (base+4) survived the prune (fail closed).
	var keptCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM provider_audit_events WHERE seq = $1`, base+4).Scan(&keptCount); err != nil {
		t.Fatalf("count kept: %v", err)
	}
	if keptCount != 1 {
		t.Fatalf("aged-but-unexported row (seq %d) must survive: count=%d", base+4, keptCount)
	}

	// A second prune at the same watermark is idempotent (nothing left to prune
	// at/under it that is also aged).
	if again, err := pruneProviderWithProof(
		ctx,
		pool,
		policy,
		verifiedWORMOnlyProof(watermark),
		time.Now(),
	); err != nil || again != 0 {
		t.Fatalf("idempotent re-prune = (%d,%v), want (0,nil)", again, err)
	}
}

func verifiedWORMOnlyProof(watermark int64) ProviderRetentionProof {
	return ProviderRetentionProof{
		watermark: watermark,
		verified:  true,
	}
}

func TestRetentionRunnerPrunesExportedPrefixesAndKeepsProjection(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("audit-retention-%d", time.Now().UnixNano()), "AuditRetention")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tid := tenancy.ID(tn.ID)
	subject := "alice@example.com"
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)

	providerBase, err := ProviderHeadSeq(ctx, pool)
	if err != nil {
		t.Fatalf("provider head: %v", err)
	}
	wantProviderPruned := int64(0)
	providerProof := ProviderRetentionProofFunc(
		func(context.Context) (ProviderRetentionProof, error) {
			return verifiedWORMOnlyProof(0), nil
		},
	)
	if providerBase == 0 {
		for i := 0; i < 4; i++ {
			if _, err := ProviderAppend(ctx, pool, "operator-x", "provider.retention.seed",
				fmt.Sprintf("provider-%d", i), map[string]any{"i": i}); err != nil {
				t.Fatalf("append provider %d: %v", i, err)
			}
		}
		if _, err := pool.Exec(ctx,
			`UPDATE provider_audit_events SET created_at = $1 WHERE seq > $2 AND seq <= $3`,
			old, providerBase, providerBase+3); err != nil {
			t.Fatalf("backdate provider: %v", err)
		}
		wantProviderPruned = 2
		providerProof = func(context.Context) (ProviderRetentionProof, error) {
			return verifiedWORMOnlyProof(providerBase + 2), nil
		}
	}

	err = tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, func(ctx context.Context, s tenancy.Scope) error {
		if _, err := TenantAppend(ctx, s, "auditor", "tenant.old.exported.1", "config", map[string]any{"i": 1}); err != nil {
			return err
		}
		if _, err := TenantAppend(ctx, s, "auditor", "tenant.old.exported.2", "config", map[string]any{"i": 2}); err != nil {
			return err
		}
		if _, err := TenantAppend(ctx, s, subject, "tenant.old.unexported", subject, map[string]any{"email": subject}); err != nil {
			return err
		}
		if _, err := TenantAppend(ctx, s, subject, "tenant.fresh.exported", subject, map[string]any{"email": subject}); err != nil {
			return err
		}
		if _, err := RecordSubjectErasure(ctx, s, "privacy-admin", subject, "dsar"); err != nil {
			return err
		}
		return (store.SIEMDelivery{}).Advance(ctx, s, 2)
	})
	if err != nil {
		t.Fatalf("seed tenant audit: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE audit_events SET created_at = $1 WHERE tenant_id = $2 AND seq <= 3`,
		old, tn.ID); err != nil {
		t.Fatalf("backdate tenant: %v", err)
	}

	runner := NewRetentionRunnerPG(pool, RetentionPolicy{Window: 24 * time.Hour}, nil, testLog()).
		WithProviderRetentionProof(providerProof).
		WithTenantIDsForTest(func(context.Context) ([]string, error) { return []string{tn.ID}, nil }).
		WithNowForTest(func() time.Time { return now })
	sum, err := runner.Tick(ctx)
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if sum.ProviderPruned != wantProviderPruned || sum.TenantPruned != 2 || sum.TenantsChecked != 1 {
		t.Fatalf("summary = %+v, want provider=%d tenant=2 tenants=1", sum, wantProviderPruned)
	}

	if providerBase == 0 {
		assertProviderSeqAbsent(t, pool, providerBase+1)
		assertProviderSeqAbsent(t, pool, providerBase+2)
		assertProviderSeqPresent(t, pool, providerBase+3)
		assertProviderSeqPresent(t, pool, providerBase+4)
		if err := ProviderVerifyFrom(ctx, pool, providerBase+3); err != nil {
			t.Fatalf("kept provider suffix must verify: %v", err)
		}
	}

	err = tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, func(ctx context.Context, s tenancy.Scope) error {
		assertTenantSeqAbsent(t, pool, tn.ID, 1)
		assertTenantSeqAbsent(t, pool, tn.ID, 2)
		assertTenantSeqPresent(t, pool, tn.ID, 3)
		assertTenantSeqPresent(t, pool, tn.ID, 4)
		if err := tenantVerifyFrom(ctx, s, 3); err != nil {
			return fmt.Errorf("kept tenant suffix must verify: %w", err)
		}
		events, err := List(ctx, s, 0, 100)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(events)
		if strings.Contains(string(raw), subject) {
			return fmt.Errorf("subject projection leaked %q in %s", subject, raw)
		}
		if !strings.Contains(string(raw), erasedSubjectValue) {
			return fmt.Errorf("subject projection missing erased marker in %s", raw)
		}
		if !strings.Contains(string(raw), RetentionPruneAction) {
			return fmt.Errorf("tenant prune receipt missing in %s", raw)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestTenantSubjectErasureRetentionProjection is the regression for
// DATA-85020084. A privacy.subject_erase event is evidence, not a permanent
// retention barrier: once it is old and exported, the marker and later eligible
// rows may leave Postgres while the tenant-scoped subject projection remains.
func TestTenantSubjectErasureRetentionProjection(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	stamp := time.Now().UnixNano()
	tenantA, err := store.NewTenants(pool).Create(
		ctx,
		fmt.Sprintf("audit-erasure-retention-a-%d", stamp),
		"Audit Erasure Retention A",
	)
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tenantB, err := store.NewTenants(pool).Create(
		ctx,
		fmt.Sprintf("audit-erasure-retention-b-%d", stamp),
		"Audit Erasure Retention B",
	)
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM tenants WHERE id = $1::uuid OR id = $2::uuid`,
			tenantA.ID,
			tenantB.ID,
		)
	})

	subjectA := "retained-alice@example.test"
	subjectB := "retained-bob@example.test"
	for _, tc := range []struct {
		tenantID string
		subject  string
	}{
		{tenantID: tenantA.ID, subject: subjectA},
		{tenantID: tenantB.ID, subject: subjectB},
	} {
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tc.tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				if _, err := TenantAppend(
					ctx,
					scope,
					tc.subject,
					"directory.before_erasure",
					tc.subject,
					map[string]any{"email": tc.subject},
				); err != nil {
					return err
				}
				if _, err := RecordSubjectErasure(
					ctx,
					scope,
					"privacy-admin",
					tc.subject,
					"retention regression",
				); err != nil {
					return err
				}
				_, err := TenantAppend(
					ctx,
					scope,
					tc.subject,
					"directory.after_erasure",
					tc.subject,
					map[string]any{"email": tc.subject},
				)
				if err != nil {
					return err
				}
				return (store.SIEMDelivery{}).Advance(ctx, scope, 3)
			},
		)
		if err != nil {
			t.Fatalf("seed tenant %s: %v", tc.tenantID, err)
		}
	}

	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	if _, err := pool.Exec(
		ctx,
		`UPDATE audit_events
		    SET created_at = $1
		  WHERE tenant_id = $2::uuid`,
		old,
		tenantA.ID,
	); err != nil {
		t.Fatalf("backdate tenant A: %v", err)
	}

	policy := RetentionPolicy{Window: 24 * time.Hour}
	if pruned, err := PruneTenant(
		ctx,
		pool,
		tenantA.ID,
		policy,
		3,
		now,
	); err != nil || pruned != 3 {
		t.Fatalf("prune marker-spanning prefix = (%d, %v), want (3, nil)", pruned, err)
	}
	if pruned, err := PruneTenant(
		ctx,
		pool,
		tenantA.ID,
		policy,
		3,
		now,
	); err != nil || pruned != 0 {
		t.Fatalf("repeat marker-spanning prune = (%d, %v), want (0, nil)", pruned, err)
	}

	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantA.ID)),
		pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			if _, err := TenantAppend(
				ctx,
				scope,
				subjectA,
				"directory.future",
				subjectA,
				map[string]any{"email": subjectA},
			); err != nil {
				return err
			}
			events, err := List(ctx, scope, 0, 100)
			if err != nil {
				return err
			}
			raw, err := json.Marshal(events)
			if err != nil {
				return err
			}
			if strings.Contains(strings.ToLower(string(raw)), subjectA) {
				return fmt.Errorf("durable projection leaked subject after marker prune: %s", raw)
			}
			if !strings.Contains(string(raw), erasedSubjectValue) {
				return fmt.Errorf("durable projection token missing after marker prune: %s", raw)
			}
			var own, other int
			if err := scope.Q.QueryRow(
				ctx,
				`SELECT count(*) FROM audit_subject_erasures`,
			).Scan(&own); err != nil {
				return err
			}
			if err := scope.Q.QueryRow(
				ctx,
				`SELECT count(*)
				   FROM audit_subject_erasures
				  WHERE tenant_id = $1::uuid`,
				tenantB.ID,
			).Scan(&other); err != nil {
				return err
			}
			if own != 1 || other != 0 {
				return fmt.Errorf(
					"tenant A projection RLS own/all=%d tenant-B=%d, want 1/0",
					own,
					other,
				)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	var tenantBEvents int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid`,
		tenantB.ID,
	).Scan(&tenantBEvents); err != nil {
		t.Fatalf("count tenant B audit rows: %v", err)
	}
	if tenantBEvents != 3 {
		t.Fatalf("tenant B audit rows = %d, want unchanged 3", tenantBEvents)
	}
}

func TestSubjectErasureRetentionProjectionAtomicWithMarker(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tenant, err := store.NewTenants(pool).Create(
		ctx,
		fmt.Sprintf("audit-erasure-atomic-%d", time.Now().UnixNano()),
		"Audit Erasure Atomic",
	)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM tenants WHERE id = $1::uuid`,
			tenant.ID,
		)
	})
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenant.ID))
	if err := tenancy.InTenant(tctx, pool, func(ctx context.Context, scope tenancy.Scope) error {
		_, err := TenantAppend(
			ctx,
			scope,
			"atomic-test",
			"projection.seed",
			tenant.ID,
			nil,
		)
		return err
	}); err != nil {
		t.Fatalf("seed audit stream: %v", err)
	}

	var realHeadHash string
	if err := pool.QueryRow(
		ctx,
		`SELECT head_hash
		   FROM audit_stream_heads
		  WHERE tenant_id = $1::uuid`,
		tenant.ID,
	).Scan(&realHeadHash); err != nil {
		t.Fatalf("read real audit head: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE audit_stream_heads
		    SET head_hash = 'corrupt-for-atomic-rollback'
		  WHERE tenant_id = $1::uuid`,
		tenant.ID,
	); err != nil {
		t.Fatalf("inject audit head mismatch: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`UPDATE audit_stream_heads
			    SET head_hash = $2
			  WHERE tenant_id = $1::uuid`,
			tenant.ID,
			realHeadHash,
		)
	})

	subject := "atomic-projection@example.test"
	err = tenancy.InTenant(tctx, pool, func(ctx context.Context, scope tenancy.Scope) error {
		_, err := RecordSubjectErasure(
			ctx,
			scope,
			"privacy-admin",
			subject,
			"atomic rollback regression",
		)
		return err
	})
	if err == nil {
		t.Fatal("subject erasure unexpectedly committed against a corrupt audit head")
	}

	var projectionRows, markerRows int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM audit_subject_erasures
		  WHERE tenant_id = $1::uuid
		    AND subject_hash = $2`,
		tenant.ID,
		SubjectErasureHash(tenant.ID, subject),
	).Scan(&projectionRows); err != nil {
		t.Fatalf("count rolled-back projection: %v", err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM audit_events
		  WHERE tenant_id = $1::uuid
		    AND action = $2`,
		tenant.ID,
		SubjectErasureAction,
	).Scan(&markerRows); err != nil {
		t.Fatalf("count rolled-back marker: %v", err)
	}
	if projectionRows != 0 || markerRows != 0 {
		t.Fatalf(
			"failed subject erasure committed projection/marker = %d/%d, want 0/0",
			projectionRows,
			markerRows,
		)
	}
}

func assertProviderSeqAbsent(t *testing.T, pool *pgxpool.Pool, seq int64) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM provider_audit_events WHERE seq = $1`, seq).Scan(&count); err != nil {
		t.Fatalf("count provider seq %d: %v", seq, err)
	}
	if count != 0 {
		t.Fatalf("provider seq %d count=%d, want absent", seq, count)
	}
}

func assertProviderSeqPresent(t *testing.T, pool *pgxpool.Pool, seq int64) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM provider_audit_events WHERE seq = $1`, seq).Scan(&count); err != nil {
		t.Fatalf("count provider seq %d: %v", seq, err)
	}
	if count != 1 {
		t.Fatalf("provider seq %d count=%d, want present", seq, count)
	}
}

func assertTenantSeqAbsent(t *testing.T, pool *pgxpool.Pool, tenantID string, seq int64) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND seq = $2`, tenantID, seq).Scan(&count); err != nil {
		t.Fatalf("count tenant seq %d: %v", seq, err)
	}
	if count != 0 {
		t.Fatalf("tenant seq %d count=%d, want absent", seq, count)
	}
}

func assertTenantSeqPresent(t *testing.T, pool *pgxpool.Pool, tenantID string, seq int64) {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND seq = $2`, tenantID, seq).Scan(&count); err != nil {
		t.Fatalf("count tenant seq %d: %v", seq, err)
	}
	if count != 1 {
		t.Fatalf("tenant seq %d count=%d, want present", seq, count)
	}
}

type retentionCaptureSink struct {
	events []Event
}

func (s *retentionCaptureSink) Export(_ context.Context, _ string, ev Event) error {
	s.events = append(s.events, ev)
	return nil
}

// TestAuditRetentionAnchorSequenceAndCursorVisibility is the IR-baec5355 regression:
// retention must not derive the next sequence/hash from prunable event rows.
// It uses two real tenant streams (one fully pruned, one partially pruned) and
// an isolated real provider stream. After pruning, appends must remain above
// the already-durable SIEM/WORM cursors and be visible immediately.
func TestAuditRetentionAnchorSequenceAndCursorVisibility(t *testing.T) {
	t.Run("two tenant streams and SIEM cursors", func(t *testing.T) {
		ctx := context.Background()
		pool := setup(ctx, t)
		defer pool.Close()

		now := time.Now().UTC()
		old := now.Add(-48 * time.Hour)
		policy := RetentionPolicy{Window: 24 * time.Hour}

		tenantA, err := store.NewTenants(pool).Create(
			ctx,
			fmt.Sprintf("audit-anchor-full-%d", time.Now().UnixNano()),
			"Audit Anchor Full",
		)
		if err != nil {
			t.Fatalf("create full-prune tenant: %v", err)
		}
		tenantB, err := store.NewTenants(pool).Create(
			ctx,
			fmt.Sprintf("audit-anchor-partial-%d", time.Now().UnixNano()),
			"Audit Anchor Partial",
		)
		if err != nil {
			t.Fatalf("create partial-prune tenant: %v", err)
		}

		for _, tenant := range []struct {
			id     string
			prefix string
		}{
			{id: tenantA.ID, prefix: "full"},
			{id: tenantB.ID, prefix: "partial"},
		} {
			err := tenancy.InTenant(
				tenancy.WithTenant(ctx, tenancy.ID(tenant.id)),
				pool,
				func(ctx context.Context, s tenancy.Scope) error {
					for i := 1; i <= 4; i++ {
						if _, err := TenantAppend(
							ctx,
							s,
							"anchor-test",
							"retention.seed",
							fmt.Sprintf("%s-%d", tenant.prefix, i),
							map[string]any{"i": i},
						); err != nil {
							return err
						}
					}
					cursor := int64(2)
					if tenant.id == tenantA.ID {
						cursor = 4
					}
					return (store.SIEMDelivery{}).Advance(ctx, s, cursor)
				},
			)
			if err != nil {
				t.Fatalf("seed tenant %s: %v", tenant.prefix, err)
			}
		}

		if _, err := pool.Exec(
			ctx,
			`UPDATE audit_events SET created_at = $1 WHERE tenant_id = $2`,
			old,
			tenantA.ID,
		); err != nil {
			t.Fatalf("backdate full-prune stream: %v", err)
		}
		if _, err := pool.Exec(
			ctx,
			`UPDATE audit_events SET created_at = $1 WHERE tenant_id = $2 AND seq <= 2`,
			old,
			tenantB.ID,
		); err != nil {
			t.Fatalf("backdate partial-prune stream: %v", err)
		}

		if n, err := PruneTenant(ctx, pool, tenantA.ID, policy, 4, now); err != nil || n != 4 {
			t.Fatalf("full tenant prune = (%d, %v), want (4, nil)", n, err)
		}
		if n, err := PruneTenant(ctx, pool, tenantB.ID, policy, 2, now); err != nil || n != 2 {
			t.Fatalf("partial tenant prune = (%d, %v), want (2, nil)", n, err)
		}

		for _, tenant := range []struct {
			id          string
			oldCursor   int64
			wantFirst   int64
			wantLast    int64
			wantTargets []string
		}{
			{
				id: tenantA.ID, oldCursor: 4, wantFirst: 5, wantLast: 6,
				wantTargets: []string{"audit/" + tenantA.ID, "full-after-prune"},
			},
			{
				id: tenantB.ID, oldCursor: 2, wantFirst: 3, wantLast: 6,
				wantTargets: []string{"partial-3", "partial-4", "audit/" + tenantB.ID, "partial-after-prune"},
			},
		} {
			err := tenancy.InTenant(
				tenancy.WithTenant(ctx, tenancy.ID(tenant.id)),
				pool,
				func(ctx context.Context, s tenancy.Scope) error {
					target := "partial-after-prune"
					if tenant.id == tenantA.ID {
						target = "full-after-prune"
					}
					ev, err := TenantAppend(
						ctx,
						s,
						"anchor-test",
						"retention.after",
						target,
						nil,
					)
					if err != nil {
						return err
					}
					if ev.Seq != tenant.wantLast {
						return fmt.Errorf(
							"post-prune append seq = %d, want %d above cursor %d",
							ev.Seq,
							tenant.wantLast,
							tenant.oldCursor,
						)
					}
					if err := TenantVerify(ctx, s); err != nil {
						return fmt.Errorf("retention-aware verify: %w", err)
					}
					var visibleHeads, crossHeads int
					if err := s.Q.QueryRow(
						ctx,
						`SELECT count(*) FROM public.audit_stream_heads`,
					).Scan(&visibleHeads); err != nil {
						return err
					}
					otherID := tenantA.ID
					if tenant.id == tenantA.ID {
						otherID = tenantB.ID
					}
					if err := s.Q.QueryRow(
						ctx,
						`SELECT count(*)
						   FROM public.audit_stream_heads
						  WHERE tenant_id = $1::uuid`,
						otherID,
					).Scan(&crossHeads); err != nil {
						return err
					}
					if visibleHeads != 1 || crossHeads != 0 {
						return fmt.Errorf(
							"head RLS visibility = own/all %d cross %d, want 1/0",
							visibleHeads,
							crossHeads,
						)
					}
					cursor, err := (store.SIEMDelivery{}).Cursor(ctx, s)
					if err != nil {
						return err
					}
					if cursor != tenant.oldCursor {
						return fmt.Errorf("SIEM cursor = %d, want %d", cursor, tenant.oldCursor)
					}
					sink := &retentionCaptureSink{}
					next, err := Drain(ctx, s, sink, cursor, 100)
					if err != nil {
						return err
					}
					if next != tenant.wantLast {
						return fmt.Errorf("SIEM drain cursor = %d, want %d", next, tenant.wantLast)
					}
					if len(sink.events) != len(tenant.wantTargets) {
						return fmt.Errorf(
							"SIEM delivered %d events, want %d: %#v",
							len(sink.events),
							len(tenant.wantTargets),
							sink.events,
						)
					}
					if sink.events[0].Seq != tenant.wantFirst {
						return fmt.Errorf(
							"SIEM first seq = %d, want %d",
							sink.events[0].Seq,
							tenant.wantFirst,
						)
					}
					for i, wantTarget := range tenant.wantTargets {
						if sink.events[i].Target != wantTarget {
							return fmt.Errorf(
								"SIEM event %d target = %q, want %q",
								i,
								sink.events[i].Target,
								wantTarget,
							)
						}
					}
					return nil
				},
			)
			if err != nil {
				t.Fatalf("tenant %s post-prune proof: %v", tenant.id, err)
			}
		}

		var originalAnchorHash string
		if err := pool.QueryRow(
			ctx,
			`UPDATE public.audit_stream_heads
			    SET pruned_hash = 'tampered-anchor'
			  WHERE tenant_id = $1::uuid
			  RETURNING (
			      SELECT prev_hash
			        FROM audit_events
			       WHERE tenant_id = $1::uuid
			       ORDER BY seq
			       LIMIT 1
			  )`,
			tenantB.ID,
		).Scan(&originalAnchorHash); err != nil {
			t.Fatalf("tamper partial-prune anchor: %v", err)
		}
		err = tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantB.ID)),
			pool,
			TenantVerify,
		)
		if err == nil || !strings.Contains(err.Error(), "retention boundary broken") {
			t.Fatalf("tampered prune anchor verify error = %v, want retention-boundary failure", err)
		}
		if _, err := pool.Exec(
			ctx,
			`UPDATE public.audit_stream_heads SET pruned_hash = $2 WHERE tenant_id = $1::uuid`,
			tenantB.ID,
			originalAnchorHash,
		); err != nil {
			t.Fatalf("restore partial-prune anchor: %v", err)
		}
		if err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantB.ID)),
			pool,
			TenantVerify,
		); err != nil {
			t.Fatalf("verify restored partial-prune anchor: %v", err)
		}
	})

	t.Run("provider stream and WORM cursor", func(t *testing.T) {
		ctx := context.Background()
		admin := setup(ctx, t)
		defer admin.Close()
		pool := isolatedProviderRetentionPool(t, admin)
		defer pool.Close()

		for i := 1; i <= 3; i++ {
			if _, err := ProviderAppend(
				ctx,
				pool,
				"provider-anchor-test",
				"retention.seed",
				fmt.Sprintf("provider-%d", i),
				map[string]any{"i": i},
			); err != nil {
				t.Fatalf("append provider seed %d: %v", i, err)
			}
		}

		objects := objectstore.NewMemory()
		worm, err := NewWormExporterEphemeralForTest(
			func(ctx context.Context, afterSeq int64, limit int) ([]Event, error) {
				return ListProvider(ctx, pool, afterSeq, limit)
			},
			objects,
			testLog(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := worm.ExportOnce(ctx); err != nil || n != 3 {
			t.Fatalf("initial WORM export = (%d, %v), want (3, nil)", n, err)
		}
		watermark, err := worm.ExportedWatermark(ctx)
		if err != nil || watermark != 3 {
			t.Fatalf("WORM watermark = (%d, %v), want (3, nil)", watermark, err)
		}

		now := time.Now().UTC()
		if _, err := pool.Exec(
			ctx,
			`UPDATE provider_audit_events SET created_at = $1`,
			now.Add(-48*time.Hour),
		); err != nil {
			t.Fatalf("backdate provider stream: %v", err)
		}
		proof, err := worm.RetentionProof(ctx)
		if err != nil {
			t.Fatalf("verified provider retention proof: %v", err)
		}
		if n, err := pruneProviderWithProof(
			ctx,
			pool,
			RetentionPolicy{Window: 24 * time.Hour},
			proof,
			now,
		); err != nil || n != 3 {
			t.Fatalf("full provider prune = (%d, %v), want (3, nil)", n, err)
		}

		ev, err := ProviderAppend(
			ctx,
			pool,
			"provider-anchor-test",
			"retention.after",
			"provider-after-prune",
			nil,
		)
		if err != nil {
			t.Fatalf("append provider after prune: %v", err)
		}
		if ev.Seq != 5 {
			t.Fatalf("provider post-prune seq = %d, want 5 above WORM cursor 3", ev.Seq)
		}
		if err := ProviderVerify(ctx, pool); err != nil {
			t.Fatalf("retention-aware provider verify: %v", err)
		}
		if n, err := worm.ExportOnce(ctx); err != nil || n != 2 {
			t.Fatalf("post-prune WORM export = (%d, %v), want receipt+new event", n, err)
		}
		if err := worm.VerifyWORMChain(ctx); err != nil {
			t.Fatalf("WORM chain after full prune: %v", err)
		}

		// A second pass proves partial pruning too: seq 4-5 are now exported
		// and aged, while fresh/unexported seq 6 must remain. The receipt and
		// next append continue at 7-8, immediately after WORM cursor 5.
		watermark, err = worm.ExportedWatermark(ctx)
		if err != nil || watermark != 5 {
			t.Fatalf("second WORM watermark = (%d, %v), want (5, nil)", watermark, err)
		}
		if _, err := pool.Exec(
			ctx,
			`UPDATE provider_audit_events SET created_at = $1 WHERE seq <= $2`,
			now.Add(-48*time.Hour),
			watermark,
		); err != nil {
			t.Fatalf("backdate second provider prefix: %v", err)
		}
		blocker, err := ProviderAppend(
			ctx,
			pool,
			"provider-anchor-test",
			"retention.unexported",
			"provider-partial-blocker",
			nil,
		)
		if err != nil || blocker.Seq != 6 {
			t.Fatalf("append provider partial blocker = (%d, %v), want (6, nil)", blocker.Seq, err)
		}
		proof, err = worm.RetentionProof(ctx)
		if err != nil {
			t.Fatalf("second verified provider retention proof: %v", err)
		}
		if n, err := pruneProviderWithProof(
			ctx,
			pool,
			RetentionPolicy{Window: 24 * time.Hour},
			proof,
			now,
		); err != nil || n != 2 {
			t.Fatalf("partial provider prune = (%d, %v), want (2, nil)", n, err)
		}
		ev, err = ProviderAppend(
			ctx,
			pool,
			"provider-anchor-test",
			"retention.after-partial",
			"provider-after-partial-prune",
			nil,
		)
		if err != nil || ev.Seq != 8 {
			t.Fatalf("append provider after partial prune = (%d, %v), want (8, nil)", ev.Seq, err)
		}
		if err := ProviderVerify(ctx, pool); err != nil {
			t.Fatalf("provider verify after partial prune: %v", err)
		}
		if n, err := worm.ExportOnce(ctx); err != nil || n != 3 {
			t.Fatalf("WORM export after partial prune = (%d, %v), want (3, nil)", n, err)
		}
		if err := worm.VerifyWORMChain(ctx); err != nil {
			t.Fatalf("WORM chain after partial prune: %v", err)
		}
	})
}

// TestAuditRetentionReceiptRollbackPreservesSequenceAnchor proves the retention
// receipt is part of the same real-PostgreSQL transaction as deletion and the
// durable prune-anchor advance. An injected receipt failure must leave all
// three pieces untouched for both privilege domains.
func TestAuditRetentionReceiptRollbackPreservesSequenceAnchor(t *testing.T) {
	t.Run("tenant", func(t *testing.T) {
		ctx := context.Background()
		pool := setup(ctx, t)
		defer pool.Close()

		tenant, err := store.NewTenants(pool).Create(
			ctx,
			fmt.Sprintf("audit-receipt-rollback-%d", time.Now().UnixNano()),
			"Audit Receipt Rollback",
		)
		if err != nil {
			t.Fatal(err)
		}
		err = tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)),
			pool,
			func(ctx context.Context, s tenancy.Scope) error {
				for i := 1; i <= 2; i++ {
					if _, err := TenantAppend(
						ctx,
						s,
						"rollback-test",
						"retention.seed",
						fmt.Sprintf("tenant-%d", i),
						nil,
					); err != nil {
						return err
					}
				}
				return nil
			},
		)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		if _, err := pool.Exec(
			ctx,
			`UPDATE audit_events SET created_at = $1 WHERE tenant_id = $2::uuid`,
			now.Add(-48*time.Hour),
			tenant.ID,
		); err != nil {
			t.Fatal(err)
		}

		var receiptRole string
		n, err := pruneTenantWithReceipt(
			ctx,
			pool,
			tenant.ID,
			RetentionPolicy{Window: 24 * time.Hour},
			2,
			now,
			func(ctx context.Context, s tenancy.Scope, _ map[string]any) error {
				if err := s.Q.QueryRow(ctx, `SELECT current_user`).Scan(&receiptRole); err != nil {
					return err
				}
				return errors.New("injected tenant receipt failure")
			},
		)
		if err == nil || !strings.Contains(err.Error(), "injected tenant receipt failure") || n != 0 {
			t.Fatalf("failed tenant prune = (%d, %v), want rollback error", n, err)
		}
		if receiptRole != tenancy.AppRole {
			t.Fatalf("tenant receipt role = %q, want %q", receiptRole, tenancy.AppRole)
		}
		assertTenantSeqPresent(t, pool, tenant.ID, 1)
		assertTenantSeqPresent(t, pool, tenant.ID, 2)
		var headSeq, prunedSeq int64
		if err := pool.QueryRow(
			ctx,
			`SELECT head_seq, pruned_seq
			   FROM public.audit_stream_heads
			  WHERE tenant_id = $1::uuid`,
			tenant.ID,
		).Scan(&headSeq, &prunedSeq); err != nil {
			t.Fatal(err)
		}
		if headSeq != 2 || prunedSeq != 0 {
			t.Fatalf("tenant head after rollback = (%d,%d), want (2,0)", headSeq, prunedSeq)
		}
		var receipts int
		if err := pool.QueryRow(
			ctx,
			`SELECT count(*)
			   FROM audit_events
			  WHERE tenant_id = $1::uuid AND action = $2`,
			tenant.ID,
			RetentionPruneAction,
		).Scan(&receipts); err != nil {
			t.Fatal(err)
		}
		if receipts != 0 {
			t.Fatalf("tenant prune receipts after rollback = %d, want 0", receipts)
		}
	})

	t.Run("provider", func(t *testing.T) {
		ctx := context.Background()
		admin := setup(ctx, t)
		defer admin.Close()
		pool := isolatedProviderRetentionPool(t, admin)
		defer pool.Close()

		for i := 1; i <= 2; i++ {
			if _, err := ProviderAppend(
				ctx,
				pool,
				"rollback-test",
				"retention.seed",
				fmt.Sprintf("provider-%d", i),
				nil,
			); err != nil {
				t.Fatal(err)
			}
		}
		now := time.Now().UTC()
		if _, err := pool.Exec(
			ctx,
			`UPDATE provider_audit_events SET created_at = $1`,
			now.Add(-48*time.Hour),
		); err != nil {
			t.Fatal(err)
		}

		n, err := pruneProviderWithProofReceipt(
			ctx,
			pool,
			RetentionPolicy{Window: 24 * time.Hour},
			ProviderRetentionProof{watermark: 2, verified: true},
			now,
			func(context.Context, tenancy.Querier, map[string]any) error {
				return errors.New("injected provider receipt failure")
			},
		)
		if err == nil || !strings.Contains(err.Error(), "injected provider receipt failure") || n != 0 {
			t.Fatalf("failed provider prune = (%d, %v), want rollback error", n, err)
		}
		assertProviderSeqPresent(t, pool, 1)
		assertProviderSeqPresent(t, pool, 2)
		var headSeq, prunedSeq int64
		if err := pool.QueryRow(
			ctx,
			`SELECT head_seq, pruned_seq
			   FROM provider_audit_stream_head
			  WHERE singleton`,
		).Scan(&headSeq, &prunedSeq); err != nil {
			t.Fatal(err)
		}
		if headSeq != 2 || prunedSeq != 0 {
			t.Fatalf("provider head after rollback = (%d,%d), want (2,0)", headSeq, prunedSeq)
		}
		var receipts int
		if err := pool.QueryRow(
			ctx,
			`SELECT count(*) FROM provider_audit_events WHERE action = $1`,
			RetentionPruneAction,
		).Scan(&receipts); err != nil {
			t.Fatal(err)
		}
		if receipts != 0 {
			t.Fatalf("provider prune receipts after rollback = %d, want 0", receipts)
		}
	})
}

func TestAuditRetentionAnchorFailsClosedAboveLegacySIEMCursor(t *testing.T) {
	for _, tc := range []struct {
		name        string
		legacyEvent bool
	}{
		{name: "fully pruned empty stream"},
		{name: "legacy reset receipt at sequence one", legacyEvent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pool := setup(ctx, t)
			defer pool.Close()

			tenant, err := store.NewTenants(pool).Create(
				ctx,
				fmt.Sprintf("audit-legacy-anchor-%d", time.Now().UnixNano()),
				"Audit Legacy Anchor",
			)
			if err != nil {
				t.Fatal(err)
			}
			err = tenancy.InTenant(
				tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)),
				pool,
				func(ctx context.Context, s tenancy.Scope) error {
					return (store.SIEMDelivery{}).Advance(ctx, s, 5)
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			if tc.legacyEvent {
				hash, err := computeHash(
					tenant.ID,
					1,
					"system:audit-retention",
					RetentionPruneAction,
					"audit/"+tenant.ID,
					map[string]any{"legacy": true},
					genesis,
				)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := pool.Exec(
					ctx,
					`INSERT INTO audit_events
					    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
					 VALUES (
					    $1::uuid, 1, 'system:audit-retention', $2, $3,
					    '{"legacy":true}'::jsonb, '', $4
					 )`,
					tenant.ID,
					RetentionPruneAction,
					"audit/"+tenant.ID,
					hash,
				); err != nil {
					t.Fatal(err)
				}
			}

			err = tenancy.InTenant(
				tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)),
				pool,
				func(ctx context.Context, s tenancy.Scope) error {
					_, err := TenantAppend(
						ctx,
						s,
						"legacy-test",
						"retention.after",
						"must-not-append",
						nil,
					)
					return err
				},
			)
			if err == nil ||
				(!strings.Contains(err.Error(), "unrecoverable") &&
					!strings.Contains(err.Error(), "refusing to append behind")) {
				t.Fatalf("legacy full-prune append error = %v, want fail-closed cursor/head error", err)
			}
			var events, heads int
			if err := pool.QueryRow(
				ctx,
				`SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid`,
				tenant.ID,
			).Scan(&events); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(
				ctx,
				`SELECT count(*) FROM public.audit_stream_heads WHERE tenant_id = $1::uuid`,
				tenant.ID,
			).Scan(&heads); err != nil {
				t.Fatal(err)
			}
			wantEvents := 0
			if tc.legacyEvent {
				wantEvents = 1
			}
			if events != wantEvents || heads != 0 {
				t.Fatalf(
					"legacy fail-closed state = events:%d heads:%d, want events:%d heads:0",
					events,
					heads,
					wantEvents,
				)
			}
		})
	}
}

func TestAuditRetentionAnchorReconcilesRollingUpgradeBeforeCursorValidation(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tenant, err := store.NewTenants(pool).Create(
		ctx,
		fmt.Sprintf("audit-rolling-head-%d", time.Now().UnixNano()),
		"Audit Rolling Head",
	)
	if err != nil {
		t.Fatal(err)
	}
	tctx := tenancy.WithTenant(ctx, tenancy.ID(tenant.ID))
	err = tenancy.InTenant(
		tctx,
		pool,
		func(ctx context.Context, s tenancy.Scope) error {
			first, err := TenantAppend(
				ctx,
				s,
				"rolling-upgrade-test",
				"retention.seed",
				"first",
				nil,
			)
			if err != nil {
				return err
			}
			legacyData := map[string]any{"writer": "old-binary"}
			legacyHash, err := computeHash(
				tenant.ID,
				2,
				"rolling-upgrade-test",
				"retention.legacy-append",
				"second",
				legacyData,
				first.Hash,
			)
			if err != nil {
				return err
			}
			dataJSON, err := json.Marshal(legacyData)
			if err != nil {
				return err
			}
			if _, err := s.Q.Exec(
				ctx,
				`INSERT INTO audit_events
				    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
				 VALUES ($1::uuid, 2, $2, $3, $4, $5::jsonb, $6, $7)`,
				tenant.ID,
				"rolling-upgrade-test",
				"retention.legacy-append",
				"second",
				string(dataJSON),
				first.Hash,
				legacyHash,
			); err != nil {
				return err
			}
			return (store.SIEMDelivery{}).Advance(ctx, s, 2)
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	var appended Event
	err = tenancy.InTenant(
		tctx,
		pool,
		func(ctx context.Context, s tenancy.Scope) error {
			var err error
			appended, err = TenantAppend(
				ctx,
				s,
				"rolling-upgrade-test",
				"retention.new-append",
				"third",
				nil,
			)
			if err != nil {
				return err
			}
			return TenantVerify(ctx, s)
		},
	)
	if err != nil {
		t.Fatalf("reconcile old-binary extension before cursor validation: %v", err)
	}
	if appended.Seq != 3 {
		t.Fatalf("post-reconciliation append seq = %d, want 3", appended.Seq)
	}

	var headSeq int64
	if err := pool.QueryRow(
		ctx,
		`SELECT head_seq
		   FROM public.audit_stream_heads
		  WHERE tenant_id = $1::uuid`,
		tenant.ID,
	).Scan(&headSeq); err != nil {
		t.Fatal(err)
	}
	if headSeq != 3 {
		t.Fatalf("reconciled durable head = %d, want 3", headSeq)
	}
}

func TestAuditRetentionProviderCursorBoundsRollback(t *testing.T) {
	ctx := context.Background()
	admin := setup(ctx, t)
	defer admin.Close()
	pool := isolatedProviderRetentionPool(t, admin)
	defer pool.Close()

	for i := 1; i <= 3; i++ {
		if _, err := ProviderAppend(
			ctx,
			pool,
			"provider-cursor-test",
			"retention.seed",
			fmt.Sprintf("provider-%d", i),
			nil,
		); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	if _, err := pool.Exec(
		ctx,
		`UPDATE provider_audit_events SET created_at = $1`,
		now.Add(-48*time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	policy := RetentionPolicy{Window: 24 * time.Hour}

	if n, err := pruneProviderWithProof(
		ctx,
		pool,
		policy,
		verifiedWORMOnlyProof(4),
		now,
	); err == nil ||
		!strings.Contains(err.Error(), "above durable head") || n != 0 {
		t.Fatalf("above-head WORM prune = (%d, %v), want rollback error", n, err)
	}
	assertProviderRetentionState(t, pool, 3, 0, 3, 0)

	if n, err := pruneProviderWithProof(
		ctx,
		pool,
		policy,
		verifiedWORMOnlyProof(2),
		now,
	); err != nil || n != 2 {
		t.Fatalf("valid provider prune = (%d, %v), want (2, nil)", n, err)
	}
	assertProviderRetentionState(t, pool, 4, 2, 2, 1)

	if n, err := pruneProviderWithProof(
		ctx,
		pool,
		policy,
		verifiedWORMOnlyProof(1),
		now,
	); err == nil ||
		!strings.Contains(err.Error(), "behind prune anchor") || n != 0 {
		t.Fatalf("behind-anchor WORM prune = (%d, %v), want rollback error", n, err)
	}
	assertProviderRetentionState(t, pool, 4, 2, 2, 1)
}

func TestAuditRetentionProviderWORMAnchorReconcilesLegacyFullPrune(t *testing.T) {
	t.Run("verified WORM restores empty SQL anchor", func(t *testing.T) {
		ctx := context.Background()
		admin := setup(ctx, t)
		defer admin.Close()
		pool := isolatedProviderRetentionPool(t, admin)
		defer pool.Close()

		var exportedHead Event
		for i := 1; i <= 3; i++ {
			ev, err := ProviderAppend(
				ctx,
				pool,
				"provider-reconcile-test",
				"retention.seed",
				fmt.Sprintf("provider-%d", i),
				nil,
			)
			if err != nil {
				t.Fatal(err)
			}
			exportedHead = ev
		}
		objects := objectstore.NewMemory()
		worm, err := NewWormExporterEphemeralForTest(
			func(ctx context.Context, afterSeq int64, limit int) ([]Event, error) {
				return ListProvider(ctx, pool, afterSeq, limit)
			},
			objects,
			testLog(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := worm.ExportOnce(ctx); err != nil || n != 3 {
			t.Fatalf("seed WORM export = (%d, %v), want (3, nil)", n, err)
		}
		if deleted, err := objects.DeletePrefix(
			ctx,
			wormPrefix+"signing.pub",
		); err != nil || deleted != 1 {
			t.Fatalf(
				"remove legacy WORM public-key companion = (%d, %v), want (1, nil)",
				deleted,
				err,
			)
		}

		// Exact pre-0075 full-prune legacy state: signed WORM survives, but SQL
		// has neither a retained event nor durable metadata row. A complete
		// signed legacy export may also be missing only signing.pub; startup
		// verifies every signature with the configured key before repairing it.
		if _, err := pool.Exec(ctx, `DELETE FROM provider_audit_events`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM provider_audit_stream_head`); err != nil {
			t.Fatal(err)
		}
		if err := worm.ReconcileProviderHead(ctx, pool); err != nil {
			t.Fatalf("reconcile verified WORM into empty SQL: %v", err)
		}
		if err := worm.ReconcileProviderHead(ctx, pool); err != nil {
			t.Fatalf("repeat provider WORM reconciliation: %v", err)
		}
		pub, err := objects.Get(ctx, wormPrefix+"signing.pub")
		if err != nil {
			t.Fatalf("read repaired WORM public-key companion: %v", err)
		}
		if string(pub.Data) != string(worm.pubPEM) {
			t.Fatal("repaired WORM public-key companion does not match configured key")
		}

		var headSeq, prunedSeq int64
		var headHash, prunedHash string
		if err := pool.QueryRow(
			ctx,
			`SELECT head_seq, head_hash, pruned_seq, pruned_hash
			   FROM provider_audit_stream_head
			  WHERE singleton`,
		).Scan(&headSeq, &headHash, &prunedSeq, &prunedHash); err != nil {
			t.Fatal(err)
		}
		if headSeq != 4 || prunedSeq != 3 ||
			headHash == exportedHead.Hash || prunedHash != exportedHead.Hash {
			t.Fatalf(
				"reconciled provider head = (%d,%q,%d,%q), want receipt head at 4 after prune anchor (3,%q)",
				headSeq,
				headHash,
				prunedSeq,
				prunedHash,
				exportedHead.Hash,
			)
		}
		var recoveryReceipts int
		if err := pool.QueryRow(
			ctx,
			`SELECT count(*)
			   FROM provider_audit_events
			  WHERE action = $1`,
			RetentionAnchorRecoveredAction,
		).Scan(&recoveryReceipts); err != nil {
			t.Fatal(err)
		}
		if recoveryReceipts != 1 {
			t.Fatalf(
				"repeated WORM reconciliation receipts = %d, want exactly 1",
				recoveryReceipts,
			)
		}
		var receipt Event
		if err := pool.QueryRow(
			ctx,
			`SELECT seq, actor, action, target, data, prev_hash, hash, created_at
			   FROM provider_audit_events
			  WHERE seq = 4`,
		).Scan(
			&receipt.Seq,
			&receipt.Actor,
			&receipt.Action,
			&receipt.Target,
			&receipt.Data,
			&receipt.PrevHash,
			&receipt.Hash,
			&receipt.CreatedAt,
		); err != nil {
			t.Fatal(err)
		}
		if receipt.Action != RetentionAnchorRecoveredAction ||
			receipt.PrevHash != exportedHead.Hash ||
			receipt.Hash != headHash {
			t.Fatalf(
				"anchor recovery receipt = action:%q prev:%q hash:%q, want action:%q prev:%q hash:%q",
				receipt.Action,
				receipt.PrevHash,
				receipt.Hash,
				RetentionAnchorRecoveredAction,
				exportedHead.Hash,
				headHash,
			)
		}

		ev, err := ProviderAppend(
			ctx,
			pool,
			"provider-reconcile-test",
			"retention.after-reconcile",
			"provider-4",
			nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		if ev.Seq != 5 || ev.PrevHash != receipt.Hash {
			t.Fatalf(
				"post-reconciliation append = seq:%d prev:%q, want seq:5 prev:%q",
				ev.Seq,
				ev.PrevHash,
				receipt.Hash,
			)
		}
		if n, err := worm.ExportOnce(ctx); err != nil || n != 2 {
			t.Fatalf("post-reconciliation WORM export = (%d, %v), want (2, nil)", n, err)
		}
		if err := worm.VerifyWORMChain(ctx); err != nil {
			t.Fatalf("verify reconciled WORM chain: %v", err)
		}
	})

	t.Run("retained SQL disagreement fails closed", func(t *testing.T) {
		ctx := context.Background()
		admin := setup(ctx, t)
		defer admin.Close()
		pool := isolatedProviderRetentionPool(t, admin)
		defer pool.Close()

		for i := 1; i <= 2; i++ {
			if _, err := ProviderAppend(
				ctx,
				pool,
				"provider-reconcile-test",
				"retention.seed",
				fmt.Sprintf("provider-%d", i),
				nil,
			); err != nil {
				t.Fatal(err)
			}
		}
		worm, err := NewWormExporterEphemeralForTest(
			func(ctx context.Context, afterSeq int64, limit int) ([]Event, error) {
				return ListProvider(ctx, pool, afterSeq, limit)
			},
			objectstore.NewMemory(),
			testLog(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := worm.ExportOnce(ctx); err != nil || n != 2 {
			t.Fatalf("seed WORM export = (%d, %v), want (2, nil)", n, err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM provider_audit_events`); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, `DELETE FROM provider_audit_stream_head`); err != nil {
			t.Fatal(err)
		}
		reset, err := ProviderAppend(
			ctx,
			pool,
			"legacy-reset",
			RetentionPruneAction,
			"provider",
			nil,
		)
		if err != nil || reset.Seq != 1 {
			t.Fatalf("seed legacy reset = (%d, %v), want (1, nil)", reset.Seq, err)
		}

		if err := worm.ReconcileProviderHead(ctx, pool); err == nil ||
			!strings.Contains(err.Error(), "above SQL durable head") {
			t.Fatalf("reconcile retained SQL disagreement error = %v", err)
		}
		assertProviderRetentionState(t, pool, 1, 0, 1, 1)
	})

	t.Run("tampered retained suffix fails closed", func(t *testing.T) {
		ctx := context.Background()
		admin := setup(ctx, t)
		defer admin.Close()
		pool := isolatedProviderRetentionPool(t, admin)
		defer pool.Close()

		if _, err := ProviderAppend(
			ctx,
			pool,
			"provider-reconcile-test",
			"retention.seed",
			"provider-1",
			nil,
		); err != nil {
			t.Fatal(err)
		}
		worm, err := NewWormExporterEphemeralForTest(
			func(ctx context.Context, afterSeq int64, limit int) ([]Event, error) {
				return ListProvider(ctx, pool, afterSeq, limit)
			},
			objectstore.NewMemory(),
			testLog(),
		)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := worm.ExportOnce(ctx); err != nil || n != 1 {
			t.Fatalf("seed WORM export = (%d, %v), want (1, nil)", n, err)
		}
		for i := 2; i <= 3; i++ {
			if _, err := ProviderAppend(
				ctx,
				pool,
				"provider-reconcile-test",
				"retention.seed",
				fmt.Sprintf("provider-%d", i),
				nil,
			); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := pool.Exec(
			ctx,
			`UPDATE provider_audit_events SET actor = 'tampered' WHERE seq = 2`,
		); err != nil {
			t.Fatal(err)
		}

		if err := worm.ReconcileProviderHead(ctx, pool); err == nil ||
			!strings.Contains(err.Error(), "hash mismatch") {
			t.Fatalf("reconcile tampered retained suffix error = %v", err)
		}
		assertProviderRetentionState(t, pool, 3, 0, 3, 0)
		var actor string
		if err := pool.QueryRow(
			ctx,
			`SELECT actor FROM provider_audit_events WHERE seq = 2`,
		).Scan(&actor); err != nil {
			t.Fatal(err)
		}
		if actor != "tampered" {
			t.Fatalf("failed reconciliation changed tampered SQL row actor to %q", actor)
		}
	})
}

func assertProviderRetentionState(
	t *testing.T,
	pool *pgxpool.Pool,
	wantHead, wantPruned, wantEvents int64,
	wantReceipts int,
) {
	t.Helper()
	ctx := context.Background()
	var headSeq, prunedSeq, events int64
	if err := pool.QueryRow(
		ctx,
		`SELECT head_seq, pruned_seq
		   FROM provider_audit_stream_head
		  WHERE singleton`,
	).Scan(&headSeq, &prunedSeq); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM provider_audit_events`,
	).Scan(&events); err != nil {
		t.Fatal(err)
	}
	var receipts int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM provider_audit_events WHERE action = $1`,
		RetentionPruneAction,
	).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if headSeq != wantHead || prunedSeq != wantPruned ||
		events != wantEvents || receipts != wantReceipts {
		t.Fatalf(
			"provider retention state head/pruned/events/receipts = %d/%d/%d/%d, want %d/%d/%d/%d",
			headSeq,
			prunedSeq,
			events,
			receipts,
			wantHead,
			wantPruned,
			wantEvents,
			wantReceipts,
		)
	}
}

func isolatedProviderRetentionPool(t *testing.T, admin *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	schema := fmt.Sprintf("audit_retention_provider_%d", time.Now().UnixNano())
	quoted := `"` + strings.ReplaceAll(schema, `"`, `""`) + `"`
	for _, stmt := range []string{
		`CREATE SCHEMA ` + quoted,
		`CREATE TABLE ` + quoted + `.provider_audit_events
			(LIKE public.provider_audit_events INCLUDING ALL)`,
		`CREATE TABLE ` + quoted + `.provider_audit_stream_head
			(LIKE public.provider_audit_stream_head INCLUDING ALL)`,
		`GRANT USAGE ON SCHEMA ` + quoted + ` TO probectl_provider`,
		`GRANT SELECT, INSERT ON ` + quoted + `.provider_audit_events TO probectl_provider`,
		`GRANT SELECT, INSERT, UPDATE ON ` + quoted + `.provider_audit_stream_head TO probectl_provider`,
	} {
		if _, err := admin.Exec(ctx, stmt); err != nil {
			t.Fatalf("prepare isolated provider retention schema: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), `DROP SCHEMA `+quoted+` CASCADE`)
	})

	cfg := admin.Config().Copy()
	cfg.ConnConfig.RuntimeParams["search_path"] = schema + ",public"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open isolated provider retention pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping isolated provider retention pool: %v", err)
	}
	return pool
}
