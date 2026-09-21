// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantcrypto"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func tenantIDPIsolationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), testsupport.PostgresDSN())
	if err != nil {
		t.Fatal(err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		pool.Close()
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func TestTenantIdPStorageIsolation(t *testing.T) {
	ctx := context.Background()
	pool := tenantIDPIsolationPool(t)
	defer pool.Close()

	sealer, err := tenantcrypto.NewEnvelopeSealer("tenant-idp-test",
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	tenantcrypto.SetPrimary(sealer)
	t.Cleanup(tenantcrypto.Reset)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantA, err := NewTenants(pool).Create(ctx, "idp-a-"+suffix, "IdP A")
	if err != nil {
		t.Fatal(err)
	}
	tenantB, err := NewTenants(pool).Create(ctx, "idp-b-"+suffix, "IdP B")
	if err != nil {
		t.Fatal(err)
	}

	repo := TenantIDPs{}
	write := func(tenantID, issuer, secret string) {
		t.Helper()
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenantID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				_, upsertErr := repo.UpsertScoped(ctx, sc, TenantIDPInput{
					Issuer: issuer, ClientID: "probectl", ClientSecret: secret,
					RedirectURL: "https://probectl.example/auth/callback",
					Scopes:      []string{"openid", "email"}, Enabled: true,
				})
				return upsertErr
			})
		if err != nil {
			t.Fatalf("upsert %s: %v", tenantID, err)
		}
	}
	write(tenantA.ID, "https://idp-a.example", "secret-a")
	write(tenantB.ID, "https://idp-b.example", "secret-b")

	for _, tc := range []struct {
		tenantID, issuer, otherIssuer string
	}{{tenantA.ID, "https://idp-a.example", "https://idp-b.example"},
		{tenantB.ID, "https://idp-b.example", "https://idp-a.example"}} {
		err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tc.tenantID)), pool,
			func(ctx context.Context, sc tenancy.Scope) error {
				settings, getErr := repo.GetScoped(ctx, sc, false)
				if getErr != nil {
					return getErr
				}
				if settings.Issuer != tc.issuer || settings.Issuer == tc.otherIssuer {
					t.Fatalf("tenant %s read cross-tenant IdP: %+v", tc.tenantID, settings)
				}
				var rawCount int
				if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM tenant_idp`).Scan(&rawCount); err != nil {
					return err
				}
				if rawCount != 1 {
					t.Fatalf("predicate-free tenant_idp count=%d, want 1 (RLS leak)", rawCount)
				}
				otherTenantID := tenantA.ID
				if tc.tenantID == tenantA.ID {
					otherTenantID = tenantB.ID
				}
				tag, err := sc.Q.Exec(ctx, `UPDATE tenant_idp SET issuer='https://evil.example' WHERE tenant_id=$1`, otherTenantID)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 0 {
					t.Fatal("tenant updated another tenant's IdP row")
				}
				return nil
			})
		if err != nil {
			t.Fatal(err)
		}
	}

	resolvedA, err := NewTenantIDPs(pool).Get(ctx, tenantA.ID)
	if err != nil {
		t.Fatalf("tenant A secret resolution: %v", err)
	}
	if resolvedA.ClientSecret != "secret-a" {
		t.Fatalf("tenant A secret resolution=%q", resolvedA.ClientSecret)
	}
	resolvedB, err := NewTenantIDPs(pool).Get(ctx, tenantB.ID)
	if err != nil {
		t.Fatalf("tenant B secret resolution: %v", err)
	}
	if resolvedB.ClientSecret != "secret-b" {
		t.Fatalf("tenant B secret resolution=%q", resolvedB.ClientSecret)
	}

	var sealedA, sealedB string
	if err := pool.QueryRow(ctx, `SELECT client_secret_sealed FROM tenant_idp WHERE tenant_id=$1`, tenantA.ID).Scan(&sealedA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT client_secret_sealed FROM tenant_idp WHERE tenant_id=$1`, tenantB.ID).Scan(&sealedB); err != nil {
		t.Fatal(err)
	}
	if sealedA == "secret-a" || sealedB == "secret-b" || !tenantcrypto.HasScheme(sealedA) || !tenantcrypto.HasScheme(sealedB) {
		t.Fatal("IdP client secret was not envelope-sealed at rest")
	}
	if _, err := pool.Exec(ctx, `UPDATE tenant_idp SET client_secret_sealed=$1 WHERE tenant_id=$2`, sealedA, tenantB.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := NewTenantIDPs(pool).Get(ctx, tenantB.ID); err == nil {
		t.Fatal("ciphertext copied across tenants decrypted despite tenant-bound AAD")
	}
}
