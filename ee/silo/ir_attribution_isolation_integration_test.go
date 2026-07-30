// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

//go:build integration || isolation

package silo

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/crypto"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

type integrationIRKeys map[string]crypto.KeyProvider

func (k integrationIRKeys) WrapProviderForTenant(
	_ context.Context,
	tenantID string,
) (crypto.KeyProvider, error) {
	provider, ok := k[tenantID]
	if !ok {
		return nil, errors.New("test IR wrapping key unavailable")
	}
	return provider, nil
}

type failingIntegrationIRKeys struct{}

func (failingIntegrationIRKeys) WrapProviderForTenant(
	context.Context,
	string,
) (crypto.KeyProvider, error) {
	return nil, errors.New("injected IR seal failure")
}

// TestIRAttributionAtomicSealIsolationAndTamper is the pooled+silo regression
// for IR-3f573c58. It uses the real provider transaction and migration 0079.
func TestIRAttributionAtomicSealIsolationAndTamper(t *testing.T) {
	pool := irIntegrationPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	t.Cleanup(cancel)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	signingPrivate, signingPublic, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, wrappingPublic, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	wrapOnly, err := crypto.NewRSAOAEPWrapProviderPEM(wrappingPublic)
	if err != nil {
		t.Fatal(err)
	}

	for _, model := range []tenancy.IsolationModel{
		tenancy.IsolationPooled,
		tenancy.IsolationSiloed,
	} {
		t.Run(string(model), func(t *testing.T) {
			stamp := fmt.Sprintf("%d", time.Now().UnixNano())
			tenantA := irIntegrationTenant(t, pool, "ir-stage-a-"+stamp, model)
			tenantB := irIntegrationTenant(t, pool, "ir-stage-b-"+stamp, model)
			provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
			if model == tenancy.IsolationSiloed {
				for _, tenantID := range []string{tenantA, tenantB} {
					if err := provisioner.Provision(
						ctx,
						tenantID,
						"",
						tenancy.IsolationSiloed,
					); err != nil {
						t.Fatalf("provision IR silo %s: %v", tenantID, err)
					}
				}
			}
			t.Cleanup(func() {
				for _, tenantID := range []string{tenantA, tenantB} {
					table := `public.ir_attribution_records`
					if model == tenancy.IsolationSiloed {
						table = pgx.Identifier{
							SchemaName(tenantID),
							"ir_attribution_records",
						}.Sanitize()
					}
					_, _ = pool.Exec(
						context.Background(),
						`DELETE FROM `+table+` WHERE tenant_id = $1::uuid`,
						tenantID,
					)
					_, _ = pool.Exec(
						context.Background(),
						`DELETE FROM public.ir_attribution_heads
						  WHERE tenant_id = $1::uuid`,
						tenantID,
					)
					if model == tenancy.IsolationSiloed {
						_ = provisioner.Teardown(
							context.Background(),
							tenantID,
							"",
							tenancy.IsolationSiloed,
						)
					}
					_, _ = pool.Exec(
						context.Background(),
						`DELETE FROM public.tenants WHERE id = $1::uuid`,
						tenantID,
					)
				}
			})

			keys := integrationIRKeys{
				tenantA: wrapOnly,
				tenantB: wrapOnly,
			}
			sidecar, err := audit.NewIRStagePG(
				keys,
				signingPrivate,
				signingPublic,
			)
			if err != nil {
				t.Fatal(err)
			}

			plainAction := "provider.breakglass_access"
			plainTarget := "grant-plain-" + stamp
			if _, err := audit.ProviderAppend(
				ctx,
				pool,
				"operator-a@example.test",
				plainAction,
				plainTarget,
				map[string]any{"tenant": tenantA},
			); err == nil {
				t.Fatal("plain protected provider append succeeded without IR sidecar")
			}
			assertProviderTargetCount(t, pool, plainAction, plainTarget, 0)

			failingSidecar, err := audit.NewIRStagePG(
				failingIntegrationIRKeys{},
				signingPrivate,
				signingPublic,
			)
			if err != nil {
				t.Fatal(err)
			}
			failedAction := "provider.breakglass_access"
			failedTarget := "grant-failed-" + stamp
			if _, err := audit.ProviderAppendBreakGlass(
				ctx,
				pool,
				failingSidecar,
				"operator-a@example.test",
				failedAction,
				failedTarget,
				map[string]any{
					"tenant": tenantA, "surface": "results.latest",
					"reason": "seal failure",
				},
				completeIntegrationIRAttribution(
					tenantA,
					"operator-a",
					failedTarget,
					"seal failure",
				),
			); err == nil {
				t.Fatal("injected IR seal failure committed")
			}
			assertProviderTargetCount(t, pool, failedAction, failedTarget, 0)

			canary := "ir-canary-" + stamp + "@example.test"
			for _, tenantID := range []string{tenantA, tenantB} {
				for n := 0; n < 2; n++ {
					grant := fmt.Sprintf("grant-%s-%d", tenantID[:8], n)
					_, err := audit.ProviderAppendBreakGlass(
						ctx,
						pool,
						sidecar,
						canary,
						"provider.breakglass_access",
						grant,
						map[string]any{
							"tenant":  tenantID,
							"surface": "results.latest",
							"use":     n + 1,
							"reason":  "incident " + stamp,
						},
						completeIntegrationIRAttribution(
							tenantID,
							"operator-"+tenantID[:8],
							grant,
							"incident "+stamp,
						),
					)
					if err != nil {
						t.Fatalf("append tenant %s IR attribution: %v", tenantID, err)
					}
					assertProviderTargetCount(
						t,
						pool,
						"provider.breakglass_access",
						grant,
						1,
					)
				}
				if err := sidecar.VerifyTenant(ctx, pool, tenantID); err != nil {
					t.Fatalf("verify tenant %s IR chain: %v", tenantID, err)
				}
			}
			if err := audit.ProviderVerify(ctx, pool); err != nil {
				t.Fatalf("verify provider stream after atomic IR appends: %v", err)
			}

			for _, tenantID := range []string{tenantA, tenantB} {
				table := irIntegrationTable(model, tenantID)
				rows, err := pool.Query(
					ctx,
					`SELECT wrapped_dek, ciphertext
					   FROM `+table+`
					  WHERE tenant_id = $1::uuid
					  ORDER BY chain_pos`,
					tenantID,
				)
				if err != nil {
					t.Fatal(err)
				}
				var ciphertexts [][]byte
				for rows.Next() {
					var wrapped, ciphertext []byte
					if err := rows.Scan(&wrapped, &ciphertext); err != nil {
						rows.Close()
						t.Fatal(err)
					}
					raw := append(append([]byte(nil), wrapped...), ciphertext...)
					if bytes.Contains(raw, []byte(canary)) {
						rows.Close()
						t.Fatal("plaintext attribution canary found in sidecar bytes")
					}
					ciphertexts = append(ciphertexts, append([]byte(nil), ciphertext...))
				}
				rows.Close()
				if len(ciphertexts) != 2 {
					t.Fatalf("tenant %s sidecar rows = %d, want 2", tenantID, len(ciphertexts))
				}
				if bytes.Equal(ciphertexts[0], ciphertexts[1]) {
					t.Fatal("duplicate attribution produced identical ciphertext")
				}
			}

			assertIRStorageIsolation(t, pool, model, tenantA, tenantB)

			tableA := irIntegrationTable(model, tenantA)
			if _, err := pool.Exec(
				ctx,
				`UPDATE `+tableA+`
				    SET ciphertext = ciphertext || decode('00', 'hex')
				  WHERE tenant_id = $1::uuid AND chain_pos = 1`,
				tenantA,
			); err != nil {
				t.Fatalf("tamper fixture A: %v", err)
			}
			if err := sidecar.VerifyTenant(ctx, pool, tenantA); err == nil {
				t.Fatal("altered IR attribution record passed verification")
			}

			tableB := irIntegrationTable(model, tenantB)
			if _, err := pool.Exec(
				ctx,
				`DELETE FROM `+tableB+`
				  WHERE tenant_id = $1::uuid AND chain_pos = 2`,
				tenantB,
			); err != nil {
				t.Fatalf("remove fixture B: %v", err)
			}
			if err := sidecar.VerifyTenant(ctx, pool, tenantB); err == nil {
				t.Fatal("removed IR attribution record passed verification")
			}
		})
	}
}

func irIntegrationPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
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

func irIntegrationTenant(
	t *testing.T,
	pool *pgxpool.Pool,
	slug string,
	model tenancy.IsolationModel,
) string {
	t.Helper()
	var tenantID string
	if err := pool.QueryRow(
		context.Background(),
		`INSERT INTO public.tenants (slug, name, isolation_model)
		 VALUES ($1, $1, $2)
		 RETURNING id::text`,
		slug,
		string(model),
	).Scan(&tenantID); err != nil {
		t.Fatalf("create %s tenant: %v", model, err)
	}
	return tenantID
}

func completeIntegrationIRAttribution(
	tenantID, operatorID, grant, reason string,
) audit.IRAttribution {
	return audit.IRAttribution{
		Operator: operatorID,
		TenantID: tenantID,
		Grant:    grant,
		Surface:  "results.latest",
		Consent:  "tenant-approved:tenant-admin",
		Outcome:  "accessed",
		Reason:   reason,
	}
}

func assertProviderTargetCount(
	t *testing.T,
	pool interface {
		QueryRow(context.Context, string, ...any) pgx.Row
	},
	action, target string,
	want int,
) {
	t.Helper()
	var got int
	if err := pool.QueryRow(
		context.Background(),
		`SELECT count(*)
		   FROM public.provider_audit_events
		  WHERE action = $1 AND target = $2`,
		action,
		target,
	).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf(
			"provider events for %s/%s = %d, want %d",
			action,
			target,
			got,
			want,
		)
	}
}

func irIntegrationTable(model tenancy.IsolationModel, tenantID string) string {
	if model == tenancy.IsolationSiloed {
		return pgx.Identifier{
			SchemaName(tenantID),
			"ir_attribution_records",
		}.Sanitize()
	}
	return `public.ir_attribution_records`
}

func assertIRStorageIsolation(
	t *testing.T,
	pool interface {
		Begin(context.Context) (pgx.Tx, error)
	},
	model tenancy.IsolationModel,
	tenantA, tenantB string,
) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE probectl_provider`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		ctx,
		`SELECT set_config('probectl.tenant_id', $1, true)`,
		tenantA,
	); err != nil {
		t.Fatal(err)
	}
	var foreignRecords, foreignHead int
	foreignTable := `public.ir_attribution_records`
	if model == tenancy.IsolationSiloed {
		foreignTable = pgx.Identifier{
			SchemaName(tenantB),
			"ir_attribution_records",
		}.Sanitize()
	}
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM `+foreignTable+` WHERE tenant_id = $1::uuid`,
		tenantB,
	).Scan(&foreignRecords); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(
		ctx,
		`SELECT count(*) FROM public.ir_attribution_heads
		  WHERE tenant_id = $1::uuid`,
		tenantB,
	).Scan(&foreignHead); err != nil {
		t.Fatal(err)
	}
	if foreignRecords != 0 || foreignHead != 0 {
		t.Fatalf(
			"tenant A read tenant B IR state: records=%d head=%d",
			foreignRecords,
			foreignHead,
		)
	}
	ownTable := irIntegrationTable(model, tenantA)
	if _, err := tx.Exec(ctx, `SAVEPOINT ir_update_denied`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		ctx,
		`UPDATE `+ownTable+`
		    SET ciphertext = ciphertext
		  WHERE tenant_id = $1::uuid`,
		tenantA,
	); err == nil {
		t.Fatal("provider runtime updated append-only IR record")
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT ir_update_denied`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT ir_delete_denied`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		ctx,
		`DELETE FROM `+ownTable+` WHERE tenant_id = $1::uuid`,
		tenantA,
	); err == nil {
		t.Fatal("provider runtime deleted append-only IR record")
	}
	if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT ir_delete_denied`); err != nil {
		t.Fatal(err)
	}
}
