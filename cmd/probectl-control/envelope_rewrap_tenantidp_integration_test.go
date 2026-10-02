// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
)

// TestEnvelopeRewrapRotatesTenantIDPSecret is the PLAT-04 regression. The
// documented envelope-KEK rotation walked only alert_rules.channels and
// agent_ca.key_sealed, so tenant_idp.client_secret_sealed — sealed with the
// SAME deployment envelope — was left on the retired key. verify-retired then
// reported success (it never scanned tenant_idp) and removing the retired
// opener locked every tenant out of SSO (/auth/login 503). After the fix the
// rewrap set includes tenant_idp: execute rewraps it, verify fails closed while
// it still carries the retired id, and SSO login keeps working once the opener
// is gone.
func TestEnvelopeRewrapRotatesTenantIDPSecret(t *testing.T) {
	db := setupEnvelopeRewrapDB(t)
	ctx := context.Background()
	oldKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{8}, 32))
	newKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))

	tenantcrypto.Reset()
	t.Cleanup(tenantcrypto.Reset)
	oldSealer, err := tenantcrypto.NewEnvelopeSealer("old-plat04", oldKey)
	if err != nil {
		t.Fatalf("old sealer: %v", err)
	}
	tenantcrypto.SetPrimary(oldSealer)

	// Isolate tenant_idp: no agent CA and no alert rule carries the retired key,
	// so matched!=0 in verify can come only from tenant_idp.
	if _, err := db.Pool().Exec(ctx, `DELETE FROM agent_ca`); err != nil {
		t.Fatalf("reset agent_ca: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Pool().Exec(context.Background(), `DELETE FROM agent_ca`) })

	tenant, err := store.NewTenants(db.Pool()).Create(ctx, fmt.Sprintf("plat04-%d", time.Now().UnixNano()), "PLAT-04")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	const ssoSecret = "sso-rotate-me-please"
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant.ID)), db.Pool(), func(ctx context.Context, sc tenancy.Scope) error {
		_, uerr := (store.TenantIDPs{}).UpsertScoped(ctx, sc, store.TenantIDPInput{
			Issuer: "https://idp.example", ClientID: "cid-plat04", ClientSecret: ssoSecret,
			RedirectURL: "https://app.example/callback", Enabled: true,
		})
		return uerr
	}); err != nil {
		t.Fatalf("seal tenant idp secret under old key: %v", err)
	}

	// Scope the count to THIS tenant: the integration PG is shared and
	// accumulates rows across runs, so a global count would see leftovers from
	// aborted runs. (The owner pool bypasses RLS, so the explicit tenant_id
	// predicate is the isolation here.)
	countOld := func(t *testing.T) int {
		t.Helper()
		var n int
		if err := db.Pool().QueryRow(ctx,
			`SELECT count(*) FROM tenant_idp WHERE tenant_id = $1::uuid AND client_secret_sealed LIKE 'dv1:old-plat04:%'`,
			tenant.ID).Scan(&n); err != nil {
			t.Fatalf("count retired-key tenant_idp rows: %v", err)
		}
		return n
	}
	t.Cleanup(func() {
		_, _ = db.Pool().Exec(context.Background(), `DELETE FROM tenant_idp WHERE tenant_id = $1::uuid`, tenant.ID)
	})
	if countOld(t) != 1 {
		t.Fatalf("precondition: tenant_idp secret should be sealed under old-plat04")
	}

	// Rotate the deployment envelope: new primary, old kept only as an opener.
	newWithOld, err := tenantcrypto.NewEnvelopeKeyringSealer("new-plat04", newKey, map[string]string{"old-plat04": oldKey})
	if err != nil {
		t.Fatalf("new keyring: %v", err)
	}
	tenantcrypto.SetPrimary(newWithOld)
	cfg := &config.Config{EnvelopeKeyID: "new-plat04"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	// (A) verify-retired must FAIL CLOSED while tenant_idp still uses the retired
	// key. Pre-fix this returned success (tenant_idp was never scanned).
	if err := runEnvelopeRewrap(ctx, cfg, db, log, []string{"--verify-retired-key-id=old-plat04"}); err == nil || !strings.Contains(err.Error(), "old-plat04") {
		t.Fatalf("PLAT-04: verify-retired must fail closed while tenant_idp carries the retired key, got %v", err)
	}

	// (B) execute rewrap must move tenant_idp onto the active key.
	if err := runEnvelopeRewrap(ctx, cfg, db, log, []string{"--from-key-id=old-plat04"}); err != nil {
		t.Fatalf("execute rewrap: %v", err)
	}
	if n := countOld(t); n != 0 {
		t.Fatalf("PLAT-04: %d tenant_idp secret(s) still sealed with the retired key after rewrap", n)
	}

	// (C) remove the retired opener entirely; verify-retired must now pass AND the
	// tenant's SSO config must still decrypt (the /auth/login open-failure 503
	// branch must not trigger).
	tenantcrypto.Reset()
	newOnly, err := tenantcrypto.NewEnvelopeSealer("new-plat04", newKey)
	if err != nil {
		t.Fatalf("new-only sealer: %v", err)
	}
	tenantcrypto.SetPrimary(newOnly)
	if err := runEnvelopeRewrap(ctx, cfg, db, log, []string{"--verify-retired-key-id=old-plat04"}); err != nil {
		t.Fatalf("verify after rewrap + opener removal: %v", err)
	}
	idp, err := store.NewTenantIDPs(db.Pool()).Get(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("PLAT-04: tenant SSO configuration unavailable after retiring the old key (the 503 lockout): %v", err)
	}
	if idp.ClientSecret != ssoSecret {
		t.Fatalf("PLAT-04: decrypted SSO secret mismatch after rotation: got %q", idp.ClientSecret)
	}
}
