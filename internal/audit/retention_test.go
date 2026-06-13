// SPDX-License-Identifier: LicenseRef-probectl-TBD

package audit

import (
	"context"
	"testing"
	"time"
)

// TestRetentionPolicyLogic covers the pure policy logic with no database: a
// non-positive window disables pruning (keep-forever default), a positive one is
// enabled, and the cutoff is `now - window`.
func TestRetentionPolicyLogic(t *testing.T) {
	if (RetentionPolicy{}).Enabled() {
		t.Error("zero-window policy must be disabled (keep forever is the default)")
	}
	if (RetentionPolicy{Window: -time.Hour}).Enabled() {
		t.Error("negative window must be disabled")
	}
	p := RetentionPolicy{Window: 24 * time.Hour}
	if !p.Enabled() {
		t.Fatal("positive window must be enabled")
	}
	now := time.Unix(1_000_000, 0)
	if got := p.cutoff(now); !got.Equal(now.Add(-24 * time.Hour)) {
		t.Errorf("cutoff = %v, want now-window", got)
	}
}

// TestPruneFailsClosedWithoutDB asserts the guards that short-circuit BEFORE any
// SQL runs — so a misconfiguration can never delete audit history. With a nil
// pool these must return (0, nil) by hitting the guard, never panic on the pool.
func TestPruneFailsClosedWithoutDB(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	// Disabled policy: no-op even with a "watermark".
	if n, err := PruneProvider(ctx, nil, RetentionPolicy{}, 100, now); n != 0 || err != nil {
		t.Errorf("disabled policy prune = (%d,%v), want (0,nil)", n, err)
	}
	// Enabled policy but zero watermark (nothing proven exported): no-op.
	if n, err := PruneProvider(ctx, nil, RetentionPolicy{Window: time.Hour}, 0, now); n != 0 || err != nil {
		t.Errorf("zero-watermark prune = (%d,%v), want (0,nil)", n, err)
	}
	// Tenant prune: empty tenant id is a no-op.
	if n, err := PruneTenant(ctx, nil, "", RetentionPolicy{Window: time.Hour}, 100, now); n != 0 || err != nil {
		t.Errorf("empty-tenant prune = (%d,%v), want (0,nil)", n, err)
	}
	// Tenant prune: zero watermark is a no-op even with a tenant + window.
	if n, err := PruneTenant(ctx, nil, "t", RetentionPolicy{Window: time.Hour}, 0, now); n != 0 || err != nil {
		t.Errorf("zero-watermark tenant prune = (%d,%v), want (0,nil)", n, err)
	}
}
