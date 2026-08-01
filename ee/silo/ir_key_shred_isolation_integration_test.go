// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

//go:build integration || isolation

package silo

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type irShredSQLExecutor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

type irShredStorageFixture struct {
	tenantID    string
	manifest    string
	irHeadHash  string
	actorHash   string
	planEvent   string
	planHash    string
	tombEvent   string
	tombHash    string
	receiptHash string
}

func newIRShredStorageFixture(tenantID string) irShredStorageFixture {
	digest := func(label string) string {
		return fmt.Sprintf("%x", crypto.Hash([]byte(label+"|"+tenantID)))
	}
	return irShredStorageFixture{
		tenantID: tenantID,
		manifest: fmt.Sprintf(
			`{"artifacts":[{"key_id":"rsa-oaep-sha256:%s","artifact_hash":"%s"}]}`,
			digest("key"),
			digest("artifact"),
		),
		irHeadHash:  digest("ir-head"),
		actorHash:   digest("actor"),
		planEvent:   digest("plan-event"),
		planHash:    digest("plan"),
		tombEvent:   digest("tombstone-event"),
		tombHash:    digest("tombstone"),
		receiptHash: digest("destroy-receipt"),
	}
}

func (f irShredStorageFixture) insertPlan(
	ctx context.Context,
	q irShredSQLExecutor,
) error {
	_, err := q.Exec(
		ctx,
		`INSERT INTO public.ir_key_shred_records
		     (tenant_id, chain_pos, kind, plan_ref, covered_seq,
		      ir_record_count, ir_last_audit_seq, ir_last_hash,
		      artifact_manifest, actor_hash, event_ref, destroyed_count,
		      destroy_receipt_hash, prev_hash, hash, signature)
		 VALUES ($1::uuid, 1, 'plan', '', 7,
		         1, 7, $2, $3::jsonb, $4, $5, 0, '', '', $6, $7)`,
		f.tenantID,
		f.irHeadHash,
		f.manifest,
		f.actorHash,
		f.planEvent,
		f.planHash,
		bytes.Repeat([]byte{0x31}, 64),
	)
	return err
}

func (f irShredStorageFixture) insertTombstone(
	ctx context.Context,
	q irShredSQLExecutor,
) error {
	_, err := q.Exec(
		ctx,
		`INSERT INTO public.ir_key_shred_records
		     (tenant_id, chain_pos, kind, plan_ref, covered_seq,
		      ir_record_count, ir_last_audit_seq, ir_last_hash,
		      artifact_manifest, actor_hash, event_ref, destroyed_count,
		      destroy_receipt_hash, prev_hash, hash, signature)
		 VALUES ($1::uuid, 2, 'tombstone', $2, 7,
		         1, 7, $3, $4::jsonb, $5, $6, 1, $7, $2, $8, $9)`,
		f.tenantID,
		f.planHash,
		f.irHeadHash,
		f.manifest,
		f.actorHash,
		f.tombEvent,
		f.receiptHash,
		f.tombHash,
		bytes.Repeat([]byte{0x32}, 64),
	)
	return err
}

func (f irShredStorageFixture) insertHead(
	ctx context.Context,
	q irShredSQLExecutor,
) error {
	_, err := q.Exec(
		ctx,
		`INSERT INTO public.ir_key_shred_heads
		     (tenant_id, record_count, last_hash, head_signature)
		 VALUES ($1::uuid, 2, $2, $3)`,
		f.tenantID,
		f.tombHash,
		bytes.Repeat([]byte{0x33}, 64),
	)
	return err
}

// TestIRCryptoShredLedgerIsolationSurvivesDeletionTeardown is the storage-only
// regression for IR-132a1231. It proves that signed plan/tombstone evidence is
// provider-global but still tenant-GUC confined for both pooled and siloed
// tenants, remains append-only to the runtime roles, and survives silo teardown.
func TestIRCryptoShredLedgerIsolationSurvivesDeletionTeardown(t *testing.T) {
	pool := irWORMIsolationPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	t.Cleanup(cancel)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)

	for _, model := range []tenancy.IsolationModel{
		tenancy.IsolationPooled,
		tenancy.IsolationSiloed,
	} {
		t.Run(string(model), func(t *testing.T) {
			stamp := fmt.Sprintf("%s-%d", model, time.Now().UnixNano())
			tenantA := irIntegrationTenant(
				t,
				pool,
				"ir-shred-a-"+stamp,
				model,
			)
			tenantB := irIntegrationTenant(
				t,
				pool,
				"ir-shred-b-"+stamp,
				model,
			)
			if model == tenancy.IsolationSiloed {
				for _, tenantID := range []string{tenantA, tenantB} {
					if err := provisioner.Provision(
						ctx,
						tenantID,
						"",
						model,
					); err != nil {
						t.Fatalf("provision IR shred silo %s: %v", tenantID, err)
					}
				}
			}

			for _, tenantID := range []string{tenantA, tenantB} {
				for _, table := range []string{
					"ir_key_shred_records",
					"ir_key_shred_heads",
				} {
					qualified := SchemaName(tenantID) + "." + table
					var copied bool
					if err := pool.QueryRow(
						ctx,
						`SELECT to_regclass($1) IS NOT NULL`,
						qualified,
					).Scan(&copied); err != nil {
						t.Fatalf("inspect %s: %v", qualified, err)
					}
					if copied {
						t.Fatalf("provider-global IR shred table copied to %s", qualified)
					}
				}
			}

			fixtureA := newIRShredStorageFixture(tenantA)
			fixtureB := newIRShredStorageFixture(tenantB)
			if err := fixtureA.insertPlan(ctx, pool); err != nil {
				t.Fatalf("seed tenant-A IR shred plan: %v", err)
			}
			if err := fixtureA.insertTombstone(ctx, pool); err != nil {
				t.Fatalf("seed tenant-A IR shred tombstone: %v", err)
			}
			if err := fixtureA.insertHead(ctx, pool); err != nil {
				t.Fatalf("seed tenant-A IR shred head: %v", err)
			}

			// INSERT is a provider capability, so this denial specifically proves
			// the restrictive tenant-GUC RLS guard rejects another tenant's row.
			insertTx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := insertTx.Exec(ctx, `SET LOCAL ROLE probectl_provider`); err != nil {
				_ = insertTx.Rollback(ctx)
				t.Fatal(err)
			}
			if _, err := insertTx.Exec(
				ctx,
				`SELECT set_config('probectl.tenant_id', $1, true)`,
				tenantA,
			); err != nil {
				_ = insertTx.Rollback(ctx)
				t.Fatal(err)
			}
			if err := fixtureB.insertPlan(ctx, insertTx); err == nil ||
				!strings.Contains(strings.ToLower(err.Error()), "row-level security") {
				_ = insertTx.Rollback(ctx)
				t.Fatalf("tenant-A cross-tenant plan insert error = %v, want RLS denial", err)
			}
			if err := insertTx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}

			if err := fixtureB.insertPlan(ctx, pool); err != nil {
				t.Fatalf("seed tenant-B IR shred plan: %v", err)
			}
			if err := fixtureB.insertTombstone(ctx, pool); err != nil {
				t.Fatalf("seed tenant-B IR shred tombstone: %v", err)
			}
			if err := fixtureB.insertHead(ctx, pool); err != nil {
				t.Fatalf("seed tenant-B IR shred head: %v", err)
			}

			assertIRShredProviderIsolation(
				ctx,
				t,
				pool,
				tenantA,
				tenantB,
			)

			if err := provisioner.Teardown(ctx, tenantA, "", model); err != nil {
				t.Fatalf("teardown tenant A after IR key tombstone: %v", err)
			}
			var records, heads int
			if err := pool.QueryRow(
				ctx,
				`SELECT count(*) FROM public.ir_key_shred_records
				  WHERE tenant_id = $1::uuid`,
				tenantA,
			).Scan(&records); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(
				ctx,
				`SELECT count(*) FROM public.ir_key_shred_heads
				  WHERE tenant_id = $1::uuid`,
				tenantA,
			).Scan(&heads); err != nil {
				t.Fatal(err)
			}
			if records != 2 || heads != 1 {
				t.Fatalf(
					"tenant-A IR shred proof after teardown = records:%d heads:%d, want 2/1",
					records,
					heads,
				)
			}
		})
	}
}

func assertIRShredProviderIsolation(
	ctx context.Context,
	t *testing.T,
	pool interface {
		Begin(context.Context) (pgx.Tx, error)
	},
	tenantA, tenantB string,
) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
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

	for _, probe := range []struct {
		table string
		wantA int
	}{
		{table: "ir_key_shred_records", wantA: 2},
		{table: "ir_key_shred_heads", wantA: 1},
	} {
		var own, foreign int
		if err := tx.QueryRow(
			ctx,
			`SELECT count(*) FROM public.`+probe.table+`
			  WHERE tenant_id = $1::uuid`,
			tenantA,
		).Scan(&own); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(
			ctx,
			`SELECT count(*) FROM public.`+probe.table+`
			  WHERE tenant_id = $1::uuid`,
			tenantB,
		).Scan(&foreign); err != nil {
			t.Fatal(err)
		}
		if own != probe.wantA || foreign != 0 {
			t.Fatalf(
				"tenant-A %s view = own:%d foreign:%d, want %d/0",
				probe.table,
				own,
				foreign,
				probe.wantA,
			)
		}
	}

	// Head UPDATE is granted to the provider role; RLS must turn a foreign
	// tenant update into zero affected rows.
	tag, err := tx.Exec(
		ctx,
		`UPDATE public.ir_key_shred_heads
		    SET updated_at = updated_at
		  WHERE tenant_id = $1::uuid`,
		tenantB,
	)
	if err != nil {
		t.Fatalf("cross-tenant head update should be RLS-hidden: %v", err)
	}
	if tag.RowsAffected() != 0 {
		t.Fatalf("cross-tenant head update affected %d rows", tag.RowsAffected())
	}

	for _, mutation := range []struct {
		name string
		sql  string
	}{
		{
			name: "update",
			sql: `UPDATE public.ir_key_shred_records
			         SET created_at = created_at
			       WHERE tenant_id = $1::uuid`,
		},
		{
			name: "delete",
			sql: `DELETE FROM public.ir_key_shred_records
			       WHERE tenant_id = $1::uuid`,
		},
	} {
		if _, err := tx.Exec(ctx, `SAVEPOINT ir_shred_`+mutation.name); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, mutation.sql, tenantB); err == nil {
			t.Fatalf("provider runtime performed cross-tenant IR shred %s", mutation.name)
		}
		if _, err := tx.Exec(
			ctx,
			`ROLLBACK TO SAVEPOINT ir_shred_`+mutation.name,
		); err != nil {
			t.Fatal(err)
		}
	}
}
