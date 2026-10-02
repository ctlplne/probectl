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

// AUD-02: created_at is part of the audit hash chain, so back- or forward-dating
// a stored event with a single UPDATE breaks verification at that sequence.
// Pre-fix the timestamp was outside the hash and re-dating went undetected.
func TestAuditCreatedAtCoveredByHashChain(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()

	// --- tenant chain (per-tenant, isolated) ---
	tn, err := store.NewTenants(pool).Create(ctx, fmt.Sprintf("aud02-%d", time.Now().UnixNano()), "Aud02")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	tid := tenancy.ID(tn.ID)
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, func(ctx context.Context, s tenancy.Scope) error {
		for i, action := range []string{"tenant.create", "user.invite", "role.bind"} {
			if _, err := TenantAppend(ctx, s, "alice", action, fmt.Sprintf("t-%d", i), map[string]any{"i": i}); err != nil {
				return err
			}
		}
		return TenantVerify(ctx, s)
	}); err != nil {
		t.Fatalf("append + verify (clean tenant chain): %v", err)
	}

	// Re-date one event as a superuser (bypassing the append-only RLS policy).
	if _, err := pool.Exec(ctx,
		`UPDATE audit_events SET created_at = created_at + interval '1 hour' WHERE tenant_id = $1 AND seq = 2`, tn.ID); err != nil {
		t.Fatalf("re-date tenant event: %v", err)
	}
	if verr := tenancy.InTenant(tenancy.WithTenant(ctx, tid), pool, TenantVerify); verr == nil {
		t.Fatal("TenantVerify must fail after an event is re-dated (AUD-02)")
	}

	// --- provider chain (global) ---
	ev, err := ProviderAppend(ctx, pool, "operator", "provider.aud02", fmt.Sprintf("p-%d", time.Now().UnixNano()), map[string]any{"k": "v"})
	if err != nil {
		t.Fatalf("provider append: %v", err)
	}
	if err := ProviderVerify(ctx, pool); err != nil {
		t.Fatalf("provider verify (clean): %v", err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE provider_audit_events SET created_at = created_at - interval '30 minutes' WHERE seq = $1`, ev.Seq); err != nil {
		t.Fatalf("re-date provider event: %v", err)
	}
	if verr := ProviderVerify(ctx, pool); verr == nil {
		t.Fatal("ProviderVerify must fail after a provider event is re-dated (AUD-02)")
	}
	// Restore the exact created_at so the GLOBAL provider chain is left valid —
	// the provider stream is shared across the package's integration tests, so a
	// leftover tamper would break another test's from-genesis ProviderVerify.
	if _, err := pool.Exec(ctx,
		`UPDATE provider_audit_events SET created_at = $1 WHERE seq = $2`, ev.CreatedAt, ev.Seq); err != nil {
		t.Fatalf("restore provider event created_at: %v", err)
	}
	if err := ProviderVerify(ctx, pool); err != nil {
		t.Fatalf("provider chain must verify again after restoring created_at: %v", err)
	}
}
