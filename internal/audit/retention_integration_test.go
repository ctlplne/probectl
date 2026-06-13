// SPDX-License-Identifier: LicenseRef-probectl-TBD

//go:build integration

package audit

import (
	"context"
	"fmt"
	"testing"
	"time"
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
