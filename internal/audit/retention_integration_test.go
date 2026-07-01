// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

// TestProviderRetentionPrune drives the EXC-ORG-01 retention pruner against real
// Postgres: append a run of provider/break-glass events, then prune with a
// watermark + window and assert (a) only events BOTH old enough AND at/under the
// exported watermark are removed, (b) newer or un-exported events survive, and
// (c) the remaining chain STILL VERIFIES (no gap broke the hash chain a verifier
// walks). This is the regulated-profile counterpart to the append-only WORM
// export: history is retained for the window, then pruned safely.
func TestProviderRetentionPrune(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	base, err := ProviderHeadSeq(ctx, pool)
	if err != nil {
		t.Fatalf("head seq: %v", err)
	}
	if base != 0 {
		t.Skipf("provider audit stream is shared and already has %d rows; strict prefix pruning needs an isolated stream", base)
	}

	// Append 6 events on the provider chain.
	const n = 6
	for i := 0; i < n; i++ {
		if _, err := ProviderAppend(ctx, pool, "operator-x", "break_glass.access",
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
	pruned, err := PruneProvider(ctx, pool, policy, watermark, time.Now())
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
	if again, err := PruneProvider(ctx, pool, policy, watermark, time.Now()); err != nil || again != 0 {
		t.Fatalf("idempotent re-prune = (%d,%v), want (0,nil)", again, err)
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
	providerWatermark := ProviderWatermarkFunc(func(context.Context) (int64, error) { return 0, nil })
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
		providerWatermark = func(context.Context) (int64, error) { return providerBase + 2, nil }
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

	runner := NewRetentionRunnerPG(pool, RetentionPolicy{Window: 24 * time.Hour}, providerWatermark, testLog()).
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
		if err := TenantVerifyFrom(ctx, s, 3); err != nil {
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
