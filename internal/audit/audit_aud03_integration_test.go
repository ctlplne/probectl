// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package audit

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
)

// TestAUD03NewlineBoundaryTamperDetected drives the AUD-03 header fix through the
// real Append/Verify entry points (docs/guardrails.md G7-N). An event is appended
// with a newline inside its actor, then a superuser moves that newline across the
// actor/action boundary. Before AUD-03 the newline-joined header rendered the two
// tuples identically, so the forged row kept the original hash and verification
// passed — an undetected tamper. It must now fail closed.
func TestAUD03NewlineBoundaryTamperDetected(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tn, err := store.NewTenants(pool).Create(
		ctx, fmt.Sprintf("aud03-nl-%d", time.Now().UnixNano()), "Aud03NL",
	)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tid := tenancy.ID(tn.ID)

	// Append one event whose actor carries a newline, and prove the honest chain
	// verifies first.
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, func(ctx context.Context, s tenancy.Scope) error {
		if _, err := TenantAppend(ctx, s, "a\nb", "c", "tgt", map[string]any{"k": "v"}); err != nil {
			return err
		}
		return TenantVerify(ctx, s)
	}); err != nil {
		t.Fatalf("append + verify (honest newline-bearing chain): %v", err)
	}

	// Tamper as a superuser (bypassing append-only RLS): slide the newline one
	// field to the right — (actor="a\nb", action="c") -> (actor="a", action="b\nc").
	// The pair is distinct, but a raw newline join serializes both identically.
	if _, err := pool.Exec(ctx,
		`UPDATE audit_events SET actor = $2, action = $3 WHERE tenant_id = $1 AND seq = 1`,
		tn.ID, "a", "b\nc",
	); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	verr := tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, TenantVerify)
	if verr == nil {
		t.Fatal("TenantVerify must detect the actor/action newline-boundary swap (AUD-03), but reported a valid chain")
	}
	t.Logf("newline-boundary tamper correctly detected: %v", verr)
}

// TestAUD03LargeIntegerPayloadVerifies is the AUD-03 regression for the float64
// round-trip (docs/guardrails.md G7-N). 9007199254740993 == 2^53 + 1 is not
// exactly representable as a float64. Before the fix, verification decoded the
// stored jsonb into map[string]any (turning the integer into float64 =
// 9007199254740992) and re-marshaled it for the hash, so the recomputed hash no
// longer matched and an HONEST event failed to verify. Hashing the exact stored
// canonical bytes keeps it clean.
func TestAUD03LargeIntegerPayloadVerifies(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	tn, err := store.NewTenants(pool).Create(
		ctx, fmt.Sprintf("aud03-int-%d", time.Now().UnixNano()), "Aud03Int",
	)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tid := tenancy.ID(tn.ID)

	const big = int64(9007199254740993) // 2^53 + 1
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, func(ctx context.Context, s tenancy.Scope) error {
		if _, err := TenantAppend(ctx, s, "alice", "big.int", "tgt", map[string]any{"n": big}); err != nil {
			return err
		}
		// A second ordinary event proves the chain still links across the
		// large-integer record.
		if _, err := TenantAppend(ctx, s, "alice", "after", "tgt", map[string]any{"ok": true}); err != nil {
			return err
		}
		return TenantVerify(ctx, s)
	}); err != nil {
		t.Fatalf("append + verify with a 2^53+1 integer payload must succeed (AUD-03): %v", err)
	}
}
