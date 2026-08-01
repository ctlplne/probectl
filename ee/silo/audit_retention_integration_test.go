// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
)

type siloSubjectIRWrapKeys struct {
	provider crypto.KeyProvider
}

func (k siloSubjectIRWrapKeys) WrapProviderForTenant(
	_ context.Context,
	_ string,
) (crypto.KeyProvider, error) {
	return k.provider, nil
}

type siloSubjectIRFixture struct {
	auditSeq        int64
	rowJSON         string
	ciphertextHex   string
	plaintextCanary string
}

func newSiloSubjectIRStage(
	t *testing.T,
	pool *pgxpool.Pool,
) *audit.IRStagePG {
	t.Helper()
	_, publicPEM, err := crypto.GenerateRSAOAEPKeyPEM()
	if err != nil {
		t.Fatalf("generate silo subject-lifecycle IR wrapping key: %v", err)
	}
	provider, err := crypto.NewRSAOAEPWrapProviderPEM(publicPEM)
	if err != nil {
		t.Fatalf("build silo subject-lifecycle IR wrapping provider: %v", err)
	}
	signingPrivate, signingPublic, err := crypto.GenerateEd25519KeyPEM()
	if err != nil {
		t.Fatalf("generate silo subject-lifecycle IR signing key: %v", err)
	}
	stage, err := audit.NewIRStagePG(
		pool,
		siloSubjectIRWrapKeys{provider: provider},
		signingPrivate,
		signingPublic,
	)
	if err != nil {
		t.Fatalf("build silo subject-lifecycle IR sidecar: %v", err)
	}
	return stage
}

func appendSiloSubjectIRFixture(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	stage *audit.IRStagePG,
	tenantID, label string,
) siloSubjectIRFixture {
	t.Helper()
	operator := "silo-ir-subject-canary-" + label + "@example.test"
	grant := "silo-subject-lifecycle-grant-" + label
	surface := "privacy.subject.lifecycle"
	reason := "silo subject lifecycle encrypted evidence regression " + label
	event, err := audit.ProviderAppendBreakGlass(
		ctx,
		pool,
		stage,
		operator,
		"provider.breakglass_access",
		grant,
		map[string]any{
			"tenant":  tenantID,
			"surface": surface,
			"reason":  reason,
		},
		audit.IRAttribution{
			Operator: operator,
			TenantID: tenantID,
			Grant:    grant,
			Surface:  surface,
			Consent:  "tenant-approved:privacy-admin-" + label,
			Outcome:  "accessed",
			Reason:   reason,
		},
	)
	if err != nil {
		t.Fatalf("append silo subject-lifecycle IR fixture for %s: %v", tenantID, err)
	}
	fixture := readSiloSubjectIRFixture(ctx, t, pool, tenantID, event.Seq)
	fixture.plaintextCanary = operator
	return fixture
}

func readSiloSubjectIRFixture(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID string,
	auditSeq int64,
) siloSubjectIRFixture {
	t.Helper()
	fixture := siloSubjectIRFixture{auditSeq: auditSeq}
	err := tenancy.InTenantProviderMaintenance(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			return scope.Q.QueryRow(
				ctx,
				`SELECT row_to_json(sidecar)::text,
				        encode(sidecar.ciphertext, 'hex')
				   FROM (
				        SELECT tenant_id, audit_seq, chain_pos, event_ref, key_id,
				               wrapped_dek, ciphertext, prev_hash, hash, signature,
				               created_at
				          FROM ir_attribution_records
				         WHERE tenant_id = $1::uuid
				           AND audit_seq = $2
				   ) AS sidecar`,
				tenantID,
				auditSeq,
			).Scan(&fixture.rowJSON, &fixture.ciphertextHex)
		},
	)
	if err != nil {
		t.Fatalf("read silo subject-lifecycle IR fixture for %s: %v", tenantID, err)
	}
	return fixture
}

func assertSiloSubjectIRAppReadDenied(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID string,
) {
	t.Helper()
	err := tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			var count int
			return scope.Q.QueryRow(
				ctx,
				`SELECT count(*)
				   FROM ir_attribution_records
				  WHERE tenant_id = $1::uuid`,
				tenantID,
			).Scan(&count)
		},
	)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf(
			"ordinary silo/app IR read error for %s = %v, want SQLSTATE 42501",
			tenantID,
			err,
		)
	}
}

func assertSiloSubjectIRAbsentFromBundle(
	t *testing.T,
	files map[string]string,
	fixtures ...siloSubjectIRFixture,
) {
	t.Helper()
	if _, ok := files["postgres/ir_attribution_records.jsonl"]; ok {
		t.Fatal("ordinary silo lifecycle bundle exposed encrypted IR sidecar rows")
	}
	for path, raw := range files {
		for _, fixture := range fixtures {
			if strings.Contains(raw, fixture.ciphertextHex) {
				t.Fatalf("ordinary silo lifecycle bundle %s exposed IR ciphertext", path)
			}
			if strings.Contains(raw, fixture.plaintextCanary) {
				t.Fatalf("ordinary silo lifecycle bundle %s exposed IR plaintext canary", path)
			}
		}
	}
}

func TestSiloTenantExportOmitsIRAttribution(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	siloTenant := mkTenant(t, pool, "ir-export-silo-"+stamp, "siloed", "")
	pooledTenant := mkTenant(t, pool, "ir-export-pool-"+stamp, "pooled", "")
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := provisioner.Provision(
		ctx,
		siloTenant,
		"",
		tenancy.IsolationSiloed,
	); err != nil {
		t.Fatalf("provision IR full-export silo: %v", err)
	}

	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })
	t.Cleanup(func() {
		if err := provisioner.Teardown(
			context.Background(),
			siloTenant,
			"",
			tenancy.IsolationSiloed,
		); err != nil {
			t.Errorf("cleanup IR full-export silo: %v", err)
		}
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM public.ir_attribution_records
			  WHERE tenant_id = $1::uuid OR tenant_id = $2::uuid`,
			siloTenant,
			pooledTenant,
		); err != nil {
			t.Errorf("cleanup IR full-export pooled records: %v", err)
		}
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM public.ir_attribution_heads
			  WHERE tenant_id = $1::uuid OR tenant_id = $2::uuid`,
			siloTenant,
			pooledTenant,
		); err != nil {
			t.Errorf("cleanup IR full-export heads: %v", err)
		}
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants
			  WHERE id = $1::uuid OR id = $2::uuid`,
			siloTenant,
			pooledTenant,
		); err != nil {
			t.Errorf("cleanup IR full-export tenants: %v", err)
		}
	})

	canaries := map[string]string{
		siloTenant:   "silo-export-" + stamp + "@example.test",
		pooledTenant: "pooled-export-" + stamp + "@example.test",
	}
	for tenantID, canary := range canaries {
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				_, err := scope.Q.Exec(
					ctx,
					`INSERT INTO users
					       (tenant_id, email, display_name, status, user_name, attributes)
					 VALUES ($1::uuid, $2, 'Silo Export Isolation Canary',
					         'active', $2, '{}'::jsonb)`,
					tenantID,
					canary,
				)
				return err
			},
		)
		if err != nil {
			t.Fatalf("seed silo export tenant %s: %v", tenantID, err)
		}
	}

	stage := newSiloSubjectIRStage(t, pool)
	siloIR := appendSiloSubjectIRFixture(
		ctx,
		t,
		pool,
		stage,
		siloTenant,
		"export-silo-"+stamp,
	)
	pooledIR := appendSiloSubjectIRFixture(
		ctx,
		t,
		pool,
		stage,
		pooledTenant,
		"export-pool-"+stamp,
	)
	assertSiloSubjectIRAppReadDenied(ctx, t, pool, siloTenant)
	assertSiloSubjectIRAppReadDenied(ctx, t, pool, pooledTenant)

	life := tenantlife.New(pool, nil, nil, nil, nil, "", log)
	for _, tenantID := range []string{siloTenant, pooledTenant} {
		var bundle bytes.Buffer
		manifest, err := life.Export(ctx, tenantID, &bundle)
		if err != nil {
			t.Fatalf("full export for tenant %s: %v", tenantID, err)
		}
		if _, ok := manifest.Tables["ir_attribution_records"]; ok {
			t.Fatalf("tenant %s manifest exposed IR sidecar table", tenantID)
		}
		if !strings.Contains(
			strings.Join(manifest.Notes, "\n"),
			"Ordinary portability exports never include encrypted incident-response attribution.",
		) {
			t.Fatalf("tenant %s manifest omitted fixed IR exclusion policy", tenantID)
		}
		files := readTenantlifeBundle(t, bundle.Bytes())
		assertSiloSubjectIRAbsentFromBundle(t, files, siloIR, pooledIR)
		users := files["postgres/users.jsonl"]
		if !strings.Contains(users, canaries[tenantID]) {
			t.Fatalf("tenant %s export omitted its ordinary canary", tenantID)
		}
		for otherTenant, otherCanary := range canaries {
			if otherTenant != tenantID && strings.Contains(users, otherCanary) {
				t.Fatalf("tenant %s export leaked tenant %s canary", tenantID, otherTenant)
			}
		}
	}

	assertSiloSubjectIRAppReadDenied(ctx, t, pool, siloTenant)
	assertSiloSubjectIRAppReadDenied(ctx, t, pool, pooledTenant)
	if got := readSiloSubjectIRFixture(ctx, t, pool, siloTenant, siloIR.auditSeq); got.rowJSON != siloIR.rowJSON {
		t.Fatal("full export altered silo tenant encrypted IR record")
	}
	if got := readSiloSubjectIRFixture(ctx, t, pool, pooledTenant, pooledIR.auditSeq); got.rowJSON != pooledIR.rowJSON {
		t.Fatal("silo tenant export altered pooled tenant encrypted IR record")
	}
}

// TestAuditRetentionRoutesSiloAndPooledSequenceAnchors proves the privileged
// delete leg and non-bypass receipt leg use the tenant's real PostgreSQL target.
// The same full-prune transition runs for one pooled and one siloed tenant;
// neither can touch or see the other's rows/head.
func TestAuditRetentionRoutesSiloAndPooledSequenceAnchors(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	pooledID := mkTenant(t, pool, "audit-retention-pool-"+stamp, "pooled", "")
	siloedID := mkTenant(t, pool, "audit-retention-silo-"+stamp, "siloed", "")
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := provisioner.Provision(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("provision audit-retention silo: %v", err)
	}
	t.Cleanup(func() {
		if err := provisioner.Teardown(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
			t.Errorf("cleanup audit-retention silo: %v", err)
		}
	})
	schema := SchemaName(siloedID)
	quotedSchema := pgx.Identifier{schema}.Sanitize()

	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	for _, tenantID := range []string{pooledID, siloedID} {
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				for seq := 1; seq <= 3; seq++ {
					if _, err := audit.TenantAppend(
						ctx,
						scope,
						"silo-retention-test",
						"retention.seed",
						fmt.Sprintf("%s-%d", tenantID, seq),
						nil,
					); err != nil {
						return err
					}
				}
				return (store.SIEMDelivery{}).Advance(ctx, scope, 3)
			},
		)
		if err != nil {
			t.Fatalf("seed audit stream %s: %v", tenantID, err)
		}
	}

	// Put one deliberately misrouted sentinel for the *other* tenant in each
	// physical audit table. A handler predicate alone could delete these; the
	// provider-role/GUC boundary below must make both rows invisible to DELETE.
	const crossTenantSentinelSeq = int64(900000001)
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO public.audit_events
		    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1::uuid, $2, 'isolation-test', 'sentinel', 'misrouted-public',
		         '{}'::jsonb, 'sentinel-prev', 'sentinel-hash')`,
		siloedID,
		crossTenantSentinelSeq,
	); err != nil {
		t.Fatalf("seed public cross-tenant audit sentinel: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO `+quotedSchema+`.audit_events
		    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1::uuid, $2, 'isolation-test', 'sentinel', 'misrouted-silo',
		         '{}'::jsonb, 'sentinel-prev', 'sentinel-hash')`,
		pooledID,
		crossTenantSentinelSeq,
	); err != nil {
		t.Fatalf("seed silo cross-tenant audit sentinel: %v", err)
	}

	for _, tc := range []struct {
		scoped string
		other  string
	}{
		{scoped: pooledID, other: siloedID},
		{scoped: siloedID, other: pooledID},
	} {
		err := tenancy.InTenantProviderMaintenance(
			tenancy.WithTenant(ctx, tenancy.ID(tc.scoped)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				var role string
				if err := scope.Q.QueryRow(ctx, `SELECT current_user`).Scan(&role); err != nil {
					return err
				}
				if role != tenancy.ProviderRole {
					return fmt.Errorf(
						"tenant maintenance role = %q, want %q",
						role,
						tenancy.ProviderRole,
					)
				}

				var ownEvents, ownHeads int
				if err := scope.Q.QueryRow(
					ctx,
					`SELECT count(*) FROM audit_events WHERE tenant_id = $1::uuid`,
					tc.scoped,
				).Scan(&ownEvents); err != nil {
					return err
				}
				if err := scope.Q.QueryRow(
					ctx,
					`SELECT count(*)
					   FROM public.audit_stream_heads
					  WHERE tenant_id = $1::uuid`,
					tc.scoped,
				).Scan(&ownHeads); err != nil {
					return err
				}
				if ownEvents != 3 || ownHeads != 1 {
					return fmt.Errorf(
						"provider maintenance own scope events/heads = %d/%d, want 3/1",
						ownEvents,
						ownHeads,
					)
				}

				eventTag, err := scope.Q.Exec(
					ctx,
					`DELETE FROM audit_events WHERE tenant_id = $1::uuid`,
					tc.other,
				)
				if err != nil {
					return fmt.Errorf("cross-tenant audit delete probe: %w", err)
				}
				headTag, err := scope.Q.Exec(
					ctx,
					`UPDATE public.audit_stream_heads
					    SET updated_at = updated_at
					  WHERE tenant_id = $1::uuid`,
					tc.other,
				)
				if err != nil {
					return fmt.Errorf("cross-tenant audit head update probe: %w", err)
				}
				if eventTag.RowsAffected() != 0 || headTag.RowsAffected() != 0 {
					return fmt.Errorf(
						"cross-tenant maintenance mutated events/heads = %d/%d, want 0/0",
						eventTag.RowsAffected(),
						headTag.RowsAffected(),
					)
				}
				return nil
			},
		)
		if err != nil {
			t.Fatalf("prove provider maintenance boundary for %s: %v", tc.scoped, err)
		}
	}

	// The cross-tenant rows survived both provider-role mutation attempts.
	if got := countIn(t, pool, "public.audit_events", siloedID); got != 1 {
		t.Fatalf("public cross-tenant sentinel rows = %d, want 1", got)
	}
	if got := countIn(t, pool, schema+".audit_events", pooledID); got != 1 {
		t.Fatalf("silo cross-tenant sentinel rows = %d, want 1", got)
	}
	if _, err := pool.Exec(
		ctx,
		`DELETE FROM public.audit_events
		  WHERE tenant_id = $1::uuid AND seq = $2`,
		siloedID,
		crossTenantSentinelSeq,
	); err != nil {
		t.Fatalf("cleanup public cross-tenant sentinel: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`DELETE FROM `+quotedSchema+`.audit_events
		  WHERE tenant_id = $1::uuid AND seq = $2`,
		pooledID,
		crossTenantSentinelSeq,
	); err != nil {
		t.Fatalf("cleanup silo cross-tenant sentinel: %v", err)
	}

	// Receipt insertion still runs as probectl_app, but that role must remain
	// physically unable to delete even its own append-only audit row.
	for _, tenantID := range []string{pooledID, siloedID} {
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				_, err := scope.Q.Exec(
					ctx,
					`DELETE FROM audit_events WHERE tenant_id = $1::uuid AND seq = 1`,
					tenantID,
				)
				return err
			},
		)
		if err == nil {
			t.Fatalf("app role deleted append-only audit row for %s", tenantID)
		}
	}

	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.audit_events SET created_at = $1 WHERE tenant_id = $2::uuid`,
		old,
		pooledID,
	); err != nil {
		t.Fatalf("backdate pooled audit stream: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE `+quotedSchema+`.audit_events
		    SET created_at = $1
		  WHERE tenant_id = $2::uuid`,
		old,
		siloedID,
	); err != nil {
		t.Fatalf("backdate silo audit stream: %v", err)
	}

	policy := audit.RetentionPolicy{Window: 24 * time.Hour}
	for _, tenantID := range []string{pooledID, siloedID} {
		if pruned, err := audit.PruneTenant(
			ctx,
			pool,
			tenantID,
			policy,
			3,
			now,
		); err != nil || pruned != 3 {
			t.Fatalf("prune tenant %s = (%d, %v), want (3, nil)", tenantID, pruned, err)
		}
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				ev, err := audit.TenantAppend(
					ctx,
					scope,
					"silo-retention-test",
					"retention.after",
					tenantID+"-after",
					nil,
				)
				if err != nil {
					return err
				}
				if ev.Seq != 5 {
					return fmt.Errorf("post-prune seq = %d, want 5", ev.Seq)
				}
				if err := audit.TenantVerify(ctx, scope); err != nil {
					return err
				}
				var ownHeads, otherHeads int
				if err := scope.Q.QueryRow(
					ctx,
					`SELECT count(*) FROM public.audit_stream_heads`,
				).Scan(&ownHeads); err != nil {
					return err
				}
				other := pooledID
				if tenantID == pooledID {
					other = siloedID
				}
				if err := scope.Q.QueryRow(
					ctx,
					`SELECT count(*)
					   FROM public.audit_stream_heads
					  WHERE tenant_id = $1::uuid`,
					other,
				).Scan(&otherHeads); err != nil {
					return err
				}
				if ownHeads != 1 || otherHeads != 0 {
					return fmt.Errorf(
						"audit head RLS = own/all:%d other:%d, want 1/0",
						ownHeads,
						otherHeads,
					)
				}
				return nil
			},
		)
		if err != nil {
			t.Fatalf("verify tenant %s after prune: %v", tenantID, err)
		}
	}

	if got := countIn(t, pool, "public.audit_events", siloedID); got != 0 {
		t.Fatalf("siloed audit rows leaked into pooled table: %d", got)
	}
	if got := countIn(t, pool, schema+".audit_events", siloedID); got != 2 {
		t.Fatalf("siloed receipt+append rows = %d, want 2", got)
	}
	if got := countIn(t, pool, "public.audit_events", pooledID); got != 2 {
		t.Fatalf("pooled receipt+append rows = %d, want 2", got)
	}
	if got := countIn(t, pool, schema+".audit_events", pooledID); got != 0 {
		t.Fatalf("pooled audit rows leaked into silo table: %d", got)
	}
}

// TestSubjectErasureRetentionIsolationPooledAndSiloProgress proves an exported
// privacy marker is not a permanent prefix barrier in either physical routing
// mode. The marker is written in the rolling-old-binary shape (audit event
// only), so retention itself must capture the hash-only projection before the
// event disappears.
func TestSubjectErasureRetentionIsolationPooledAndSiloProgress(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	pooledID := mkTenant(t, pool, "subject-retention-pool-"+stamp, "pooled", "")
	siloedID := mkTenant(t, pool, "subject-retention-silo-"+stamp, "siloed", "")
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := provisioner.Provision(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("provision subject-retention silo: %v", err)
	}
	t.Cleanup(func() {
		if err := provisioner.Teardown(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
			t.Errorf("cleanup subject-retention silo: %v", err)
		}
	})
	schema := SchemaName(siloedID)
	quotedSchema := pgx.Identifier{schema}.Sanitize()

	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	subjects := map[string]string{
		pooledID: "pooled-subject@example.test",
		siloedID: "silo-subject@example.test",
	}
	for _, tenantID := range []string{pooledID, siloedID} {
		subject := subjects[tenantID]
		hash := audit.SubjectErasureHash(tenantID, subject)
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				if _, err := audit.TenantAppend(
					ctx,
					scope,
					subject,
					"directory.before_erasure",
					subject,
					map[string]any{"email": subject},
				); err != nil {
					return err
				}
				// Simulate a rolling old writer: it emits the immutable marker
				// but does not know about audit_subject_erasures yet.
				if _, err := audit.TenantAppend(
					ctx,
					scope,
					"privacy-admin",
					audit.SubjectErasureAction,
					"subject:"+hash[:12],
					map[string]any{"subject_hash": hash},
				); err != nil {
					return err
				}
				if _, err := audit.TenantAppend(
					ctx,
					scope,
					subject,
					"directory.after_erasure",
					subject,
					map[string]any{"email": subject},
				); err != nil {
					return err
				}
				return (store.SIEMDelivery{}).Advance(ctx, scope, 3)
			},
		)
		if err != nil {
			t.Fatalf("seed rolling-writer stream %s: %v", tenantID, err)
		}
	}

	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.audit_events
		    SET created_at = $1
		  WHERE tenant_id = $2::uuid`,
		old,
		pooledID,
	); err != nil {
		t.Fatalf("backdate pooled subject-erasure stream: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE `+quotedSchema+`.audit_events
		    SET created_at = $1
		  WHERE tenant_id = $2::uuid`,
		old,
		siloedID,
	); err != nil {
		t.Fatalf("backdate silo subject-erasure stream: %v", err)
	}

	policy := audit.RetentionPolicy{Window: 24 * time.Hour}
	if pruned, err := audit.PruneTenant(
		ctx,
		pool,
		pooledID,
		policy,
		3,
		now,
	); err != nil || pruned != 3 {
		t.Fatalf("prune pooled marker-spanning prefix = (%d, %v), want (3, nil)", pruned, err)
	}

	// The silo tenant is the two-tenant bystander for the first transition:
	// event count and durable head are unchanged, and no projection was
	// accidentally written to either physical table.
	if got := countIn(t, pool, schema+".audit_events", siloedID); got != 3 {
		t.Fatalf("silo bystander events after pooled prune = %d, want 3", got)
	}
	var siloHead, siloPruned int64
	if err := pool.QueryRow(
		ctx,
		`SELECT head_seq, pruned_seq
		   FROM public.audit_stream_heads
		  WHERE tenant_id = $1::uuid`,
		siloedID,
	).Scan(&siloHead, &siloPruned); err != nil {
		t.Fatalf("read silo bystander head: %v", err)
	}
	if siloHead != 3 || siloPruned != 0 {
		t.Fatalf("silo bystander head/pruned = %d/%d, want 3/0", siloHead, siloPruned)
	}
	if got := countIn(t, pool, "public.audit_subject_erasures", siloedID); got != 0 {
		t.Fatalf("silo projection leaked into public table: %d", got)
	}
	if got := countIn(t, pool, schema+".audit_subject_erasures", siloedID); got != 0 {
		t.Fatalf("pooled prune created silo bystander projection: %d", got)
	}

	assertProjected := func(tenantID string) {
		t.Helper()
		subject := subjects[tenantID]
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				if _, err := audit.TenantAppend(
					ctx,
					scope,
					subject,
					"directory.future",
					subject,
					map[string]any{"email": subject},
				); err != nil {
					return err
				}
				if err := audit.TenantVerify(ctx, scope); err != nil {
					return err
				}
				events, err := audit.List(ctx, scope, 0, 100)
				if err != nil {
					return err
				}
				raw, err := json.Marshal(events)
				if err != nil {
					return err
				}
				if strings.Contains(strings.ToLower(string(raw)), subject) {
					return fmt.Errorf("post-prune projection leaked %q in %s", subject, raw)
				}
				if !strings.Contains(string(raw), "[erased-subject]") {
					return fmt.Errorf("post-prune projection token missing in %s", raw)
				}
				var own, other int
				if err := scope.Q.QueryRow(
					ctx,
					`SELECT count(*) FROM audit_subject_erasures`,
				).Scan(&own); err != nil {
					return err
				}
				otherID := pooledID
				if tenantID == pooledID {
					otherID = siloedID
				}
				if err := scope.Q.QueryRow(
					ctx,
					`SELECT count(*)
					   FROM audit_subject_erasures
					  WHERE tenant_id = $1::uuid`,
					otherID,
				).Scan(&other); err != nil {
					return err
				}
				if own != 1 || other != 0 {
					return fmt.Errorf(
						"projection RLS for %s own/all=%d other=%d, want 1/0",
						tenantID,
						own,
						other,
					)
				}
				return nil
			},
		)
		if err != nil {
			t.Fatalf("verify durable projection for %s: %v", tenantID, err)
		}
		var headSeq, prunedSeq int64
		if err := pool.QueryRow(
			ctx,
			`SELECT head_seq, pruned_seq
			   FROM public.audit_stream_heads
			  WHERE tenant_id = $1::uuid`,
			tenantID,
		).Scan(&headSeq, &prunedSeq); err != nil {
			t.Fatalf("read post-prune head %s: %v", tenantID, err)
		}
		if headSeq != 5 || prunedSeq != 3 {
			t.Fatalf(
				"post-prune head for %s = %d/%d, want head=5 pruned=3",
				tenantID,
				headSeq,
				prunedSeq,
			)
		}
	}
	assertProjected(pooledID)

	pooledEventsBefore := countIn(t, pool, "public.audit_events", pooledID)
	if pruned, err := audit.PruneTenant(
		ctx,
		pool,
		siloedID,
		policy,
		3,
		now,
	); err != nil || pruned != 3 {
		t.Fatalf("prune silo marker-spanning prefix = (%d, %v), want (3, nil)", pruned, err)
	}
	if got := countIn(t, pool, "public.audit_events", pooledID); got != pooledEventsBefore {
		t.Fatalf(
			"pooled bystander events after silo prune = %d, want unchanged %d",
			got,
			pooledEventsBefore,
		)
	}
	assertProjected(siloedID)

	if got := countIn(t, pool, "public.audit_subject_erasures", pooledID); got != 1 {
		t.Fatalf("pooled projection rows = %d, want 1", got)
	}
	if got := countIn(t, pool, "public.audit_subject_erasures", siloedID); got != 0 {
		t.Fatalf("silo projection leaked into public table: %d", got)
	}
	if got := countIn(t, pool, schema+".audit_subject_erasures", siloedID); got != 1 {
		t.Fatalf("silo projection rows = %d, want 1", got)
	}
	if got := countIn(t, pool, schema+".audit_subject_erasures", pooledID); got != 0 {
		t.Fatalf("pooled projection leaked into silo table: %d", got)
	}
}

func TestSiloSubjectErasureAliasMarkersAtomicAndExportsProjectedAudit(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	victimID := mkTenant(
		t,
		pool,
		"subject-atomic-silo-"+stamp,
		"siloed",
		"",
	)
	bystanderID := mkTenant(
		t,
		pool,
		"subject-atomic-pool-"+stamp,
		"pooled",
		"",
	)
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := provisioner.Provision(
		ctx,
		victimID,
		"",
		tenancy.IsolationSiloed,
	); err != nil {
		t.Fatalf("provision subject-atomic silo: %v", err)
	}
	t.Cleanup(func() {
		if err := provisioner.Teardown(
			context.Background(),
			victimID,
			"",
			tenancy.IsolationSiloed,
		); err != nil {
			t.Errorf("cleanup subject-atomic silo: %v", err)
		}
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM tenants
			  WHERE id = $1::uuid OR id = $2::uuid`,
			victimID,
			bystanderID,
		); err != nil {
			t.Errorf("cleanup subject-atomic tenants: %v", err)
		}
	})

	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	subject := "silo-atomic-" + stamp + "@example.test"
	externalID := "silo-external-" + stamp
	seed := func(tenantID, external string) string {
		t.Helper()
		var userID string
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				if err := scope.Q.QueryRow(
					ctx,
					`INSERT INTO users
					       (tenant_id, email, display_name, status, user_name,
					        external_id, attributes)
					 VALUES ($1::uuid, $2, 'Silo Atomic Subject', 'active',
					         $2, $3, jsonb_build_object('subject', $2::text))
					 RETURNING id::text`,
					tenantID,
					subject,
					external,
				).Scan(&userID); err != nil {
					return err
				}
				_, err := audit.TenantAppend(
					ctx,
					scope,
					subject,
					"directory.subject_seed",
					subject,
					map[string]any{"email": subject, "external_id": external},
				)
				return err
			},
		)
		if err != nil {
			t.Fatalf("seed subject for %s: %v", tenantID, err)
		}
		return userID
	}
	victimUserID := seed(victimID, externalID)
	seed(bystanderID, "bystander-external-"+stamp)

	aliases := []string{subject, externalID, victimUserID}
	sort.Strings(aliases)
	failHash := audit.SubjectErasureHash(victimID, aliases[1])
	schema := SchemaName(victimID)
	projectionTable := pgx.Identifier{
		schema,
		"audit_subject_erasures",
	}.Sanitize()
	constraint := pgx.Identifier{
		"subject_alias_fail_" + stamp,
	}.Sanitize()
	if _, err := pool.Exec(
		ctx,
		`ALTER TABLE `+projectionTable+`
		   ADD CONSTRAINT `+constraint+`
		   CHECK (subject_hash <> '`+failHash+`')`,
	); err != nil {
		t.Fatalf("install second-alias failure constraint: %v", err)
	}

	life := tenantlife.New(pool, nil, nil, nil, nil, "", log)
	failed, err := life.EraseSubject(
		ctx,
		victimID,
		subject,
		"privacy-admin",
		"silo atomic rollback regression",
	)
	if err != nil {
		t.Fatalf("failed subject erasure should return its receipt: %v", err)
	}
	if failed.Complete {
		t.Fatalf("second-alias failure produced a complete receipt: %+v", failed)
	}
	if got := countIn(t, pool, schema+".users", victimID); got != 1 {
		t.Fatalf("silo identity did not roll back: %d", got)
	}
	if got := countIn(
		t,
		pool,
		schema+".audit_subject_erasures",
		victimID,
	); got != 0 {
		t.Fatalf("silo projection did not roll back: %d", got)
	}
	if got := countIn(t, pool, schema+".audit_events", victimID); got != 1 {
		t.Fatalf("silo marker/head transaction did not roll back: events=%d", got)
	}
	if got := countIn(t, pool, "public.audit_subject_erasures", victimID); got != 0 {
		t.Fatalf("failed silo erasure fell through to public projection: %d", got)
	}
	if got := countIn(t, pool, "public.audit_events", victimID); got != 0 {
		t.Fatalf("failed silo erasure fell through to public audit events: %d", got)
	}
	if got := countIn(t, pool, "public.users", bystanderID); got != 1 {
		t.Fatalf("failed silo erasure changed pooled bystander: %d", got)
	}

	if _, err := pool.Exec(
		ctx,
		`ALTER TABLE `+projectionTable+`
		   DROP CONSTRAINT `+constraint,
	); err != nil {
		t.Fatalf("remove second-alias failure constraint: %v", err)
	}
	retry, err := life.EraseSubject(
		ctx,
		victimID,
		subject,
		"privacy-admin",
		"silo atomic retry",
	)
	if err != nil {
		t.Fatalf("retry silo subject erasure: %v", err)
	}
	if !retry.Complete {
		t.Fatalf("retry silo subject erasure incomplete: %+v", retry)
	}
	if got := countIn(t, pool, schema+".users", victimID); got != 0 {
		t.Fatalf("silo identity survived successful retry: %d", got)
	}
	for _, alias := range aliases {
		var n int
		if err := pool.QueryRow(
			ctx,
			`SELECT count(*)
			   FROM `+projectionTable+`
			  WHERE tenant_id = $1::uuid
			    AND subject_hash = $2`,
			victimID,
			audit.SubjectErasureHash(victimID, alias),
		).Scan(&n); err != nil {
			t.Fatalf("count silo alias projection %q: %v", alias, err)
		}
		if n != 1 {
			t.Fatalf("silo alias projection %q = %d, want 1", alias, n)
		}
	}
	var markerCount int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*)
		   FROM `+pgx.Identifier{schema, "audit_events"}.Sanitize()+`
		  WHERE tenant_id = $1::uuid
		    AND action = $2`,
		victimID,
		audit.SubjectErasureAction,
	).Scan(&markerCount); err != nil {
		t.Fatalf("count silo alias markers: %v", err)
	}
	if markerCount != len(aliases) {
		t.Fatalf("silo alias markers = %d, want %d", markerCount, len(aliases))
	}
	if got := countIn(t, pool, "public.audit_subject_erasures", victimID); got != 0 {
		t.Fatalf("successful silo retry fell through to public projection: %d", got)
	}
	if got := countIn(t, pool, "public.users", bystanderID); got != 1 {
		t.Fatalf("successful silo retry changed pooled bystander: %d", got)
	}

	var subjectBundle bytes.Buffer
	subjectManifest, err := life.ExportSubject(
		ctx,
		victimID,
		subject,
		&subjectBundle,
		false,
	)
	if err != nil {
		t.Fatalf("export erased silo subject: %v", err)
	}
	subjectFiles := readTenantlifeBundle(t, subjectBundle.Bytes())
	subjectAudit := subjectFiles["postgres/audit_events.jsonl"]
	if strings.Contains(strings.ToLower(subjectAudit), strings.ToLower(subject)) {
		t.Fatalf("silo subject audit export leaked plaintext: %s", subjectAudit)
	}
	if !strings.Contains(subjectAudit, audit.SubjectErasureAction) ||
		!strings.Contains(subjectAudit, retry.SubjectHash) ||
		!strings.Contains(subjectAudit, `"tenant_id":"`+victimID+`"`) ||
		!strings.Contains(subjectAudit, `"id":"`) ||
		!strings.Contains(subjectAudit, `"seq"`) ||
		!strings.Contains(subjectAudit, `"prev_hash"`) ||
		!strings.Contains(subjectAudit, `"hash"`) {
		t.Fatalf("silo subject audit export lost evidence: %s", subjectAudit)
	}
	var subjectAuditRows int64
	for _, plane := range subjectManifest.Planes {
		if plane.Plane == "postgres:audit_events" {
			subjectAuditRows = plane.Rows
		}
	}
	if subjectAuditRows == 0 {
		t.Fatalf("silo subject export omitted audit receipt: %+v", subjectManifest.Planes)
	}

	var fullBundle bytes.Buffer
	fullManifest, err := life.Export(ctx, victimID, &fullBundle)
	if err != nil {
		t.Fatalf("export erased silo tenant: %v", err)
	}
	fullAudit := readTenantlifeBundle(
		t,
		fullBundle.Bytes(),
	)["postgres/audit_events.jsonl"]
	if strings.Contains(strings.ToLower(fullAudit), strings.ToLower(subject)) {
		t.Fatalf("silo full audit export leaked plaintext: %s", fullAudit)
	}
	if !strings.Contains(fullAudit, "[erased-subject]") ||
		!strings.Contains(fullAudit, audit.SubjectErasureAction) ||
		!strings.Contains(fullAudit, `"id":"`) ||
		!strings.Contains(fullAudit, `"tenant_id":"`+victimID+`"`) {
		t.Fatalf("silo full audit export lost projection/evidence: %s", fullAudit)
	}
	if fullManifest.Tables["audit_events"] == 0 {
		t.Fatalf("silo full export omitted audit receipt: %+v", fullManifest.Tables)
	}

	var bystanderBundle bytes.Buffer
	if _, err := life.Export(ctx, bystanderID, &bystanderBundle); err != nil {
		t.Fatalf("export pooled bystander: %v", err)
	}
	bystanderAudit := readTenantlifeBundle(
		t,
		bystanderBundle.Bytes(),
	)["postgres/audit_events.jsonl"]
	if !strings.Contains(
		strings.ToLower(bystanderAudit),
		strings.ToLower(subject),
	) {
		t.Fatalf("silo projection altered pooled bystander export: %s", bystanderAudit)
	}
}

func TestSiloSubjectLifecycleRetainsEncryptedIRAttribution(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	victimID := mkTenant(
		t,
		pool,
		"ir-subject-silo-"+stamp,
		"siloed",
		"",
	)
	bystanderID := mkTenant(
		t,
		pool,
		"ir-subject-pool-"+stamp,
		"pooled",
		"",
	)
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := provisioner.Provision(
		ctx,
		victimID,
		"",
		tenancy.IsolationSiloed,
	); err != nil {
		t.Fatalf("provision IR subject-lifecycle silo: %v", err)
	}

	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })
	t.Cleanup(func() {
		if err := provisioner.Teardown(
			context.Background(),
			victimID,
			"",
			tenancy.IsolationSiloed,
		); err != nil {
			t.Errorf("cleanup IR subject-lifecycle silo: %v", err)
		}
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM public.ir_attribution_records
			  WHERE tenant_id = $1::uuid OR tenant_id = $2::uuid`,
			victimID,
			bystanderID,
		); err != nil {
			t.Errorf("cleanup IR subject-lifecycle pooled records: %v", err)
		}
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM public.ir_attribution_heads
			  WHERE tenant_id = $1::uuid OR tenant_id = $2::uuid`,
			victimID,
			bystanderID,
		); err != nil {
			t.Errorf("cleanup IR subject-lifecycle heads: %v", err)
		}
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants
			  WHERE id = $1::uuid OR id = $2::uuid`,
			victimID,
			bystanderID,
		); err != nil {
			t.Errorf("cleanup IR subject-lifecycle tenants: %v", err)
		}
	})

	subject := "ir-silo-subject-" + stamp + "@example.test"
	for _, tenantID := range []string{victimID, bystanderID} {
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				if _, err := scope.Q.Exec(
					ctx,
					`INSERT INTO users
					       (tenant_id, email, display_name, status, user_name, attributes)
					 VALUES ($1::uuid, $2, 'Encrypted Silo IR Subject',
					         'active', $2,
					         jsonb_build_object('subject', $2::text))`,
					tenantID,
					subject,
				); err != nil {
					return err
				}
				_, err := audit.TenantAppend(
					ctx,
					scope,
					subject,
					"directory.subject_seed",
					subject,
					map[string]any{"email": subject},
				)
				return err
			},
		)
		if err != nil {
			t.Fatalf("seed IR subject-lifecycle tenant %s: %v", tenantID, err)
		}
	}

	stage := newSiloSubjectIRStage(t, pool)
	victimIR := appendSiloSubjectIRFixture(
		ctx,
		t,
		pool,
		stage,
		victimID,
		"victim-"+stamp,
	)
	bystanderIR := appendSiloSubjectIRFixture(
		ctx,
		t,
		pool,
		stage,
		bystanderID,
		"bystander-"+stamp,
	)
	assertSiloSubjectIRAppReadDenied(ctx, t, pool, victimID)
	assertSiloSubjectIRAppReadDenied(ctx, t, pool, bystanderID)

	sink := func(
		ctx context.Context,
		actor, action, target string,
		data map[string]any,
	) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	life := tenantlife.New(
		pool,
		nil,
		nil,
		nil,
		sink,
		"test backup policy",
		log,
	)

	var subjectBundle bytes.Buffer
	subjectManifest, err := life.ExportSubject(
		ctx,
		victimID,
		subject,
		&subjectBundle,
		false,
	)
	if err != nil {
		t.Fatalf("export silo subject with encrypted IR evidence: %v", err)
	}
	subjectFiles := readTenantlifeBundle(t, subjectBundle.Bytes())
	assertSiloSubjectIRAbsentFromBundle(t, subjectFiles, victimIR, bystanderIR)
	var irExportReceipt tenantlife.SubjectPlaneResult
	for _, plane := range subjectManifest.Planes {
		if plane.Plane == "audit:ir_attribution_encrypted" {
			irExportReceipt = plane
		}
	}
	if irExportReceipt.Status != tenantlife.SubjectStatusRetainedIR ||
		!strings.Contains(irExportReceipt.Notes, "excluded") {
		t.Fatalf("silo subject IR export receipt = %+v", irExportReceipt)
	}

	report, err := life.EraseSubject(
		ctx,
		victimID,
		subject,
		"privacy-admin",
		"retain encrypted silo IR evidence",
	)
	if err != nil {
		t.Fatalf("erase silo subject with encrypted IR evidence: %v", err)
	}
	if !report.Complete {
		t.Fatalf("silo subject erasure with encrypted IR evidence incomplete: %+v", report)
	}
	var irEraseReceipt tenantlife.SubjectPlaneResult
	for _, plane := range report.Planes {
		if plane.Plane == "audit:ir_attribution_encrypted" {
			irEraseReceipt = plane
		}
	}
	if irEraseReceipt.Status != tenantlife.SubjectStatusRetainedIR ||
		!strings.Contains(irEraseReceipt.Notes, "retained") {
		t.Fatalf("silo subject IR erasure receipt = %+v", irEraseReceipt)
	}

	schema := SchemaName(victimID)
	if got := countIn(t, pool, schema+".users", victimID); got != 0 {
		t.Fatalf("silo victim subject row survived erasure: %d", got)
	}
	if got := countIn(t, pool, "public.users", bystanderID); got != 1 {
		t.Fatalf("silo victim subject erasure changed pooled bystander: %d", got)
	}

	victimAfter := readSiloSubjectIRFixture(
		ctx,
		t,
		pool,
		victimID,
		victimIR.auditSeq,
	)
	bystanderAfter := readSiloSubjectIRFixture(
		ctx,
		t,
		pool,
		bystanderID,
		bystanderIR.auditSeq,
	)
	if victimAfter.rowJSON != victimIR.rowJSON {
		t.Fatal("silo subject erasure altered the victim encrypted IR record")
	}
	if bystanderAfter.rowJSON != bystanderIR.rowJSON {
		t.Fatal("silo subject erasure altered the pooled bystander encrypted IR record")
	}
}

func TestTenantAuditRetentionEffectivePruneSiloIsolation(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	ctx := context.Background()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	pooledID := mkTenant(t, pool, "audit-policy-pool-"+stamp, "pooled", "")
	siloedID := mkTenant(t, pool, "audit-policy-silo-"+stamp, "siloed", "")
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := provisioner.Provision(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("provision audit-policy silo: %v", err)
	}
	t.Cleanup(func() {
		if err := provisioner.Teardown(ctx, siloedID, "", tenancy.IsolationSiloed); err != nil {
			t.Errorf("cleanup audit-policy silo: %v", err)
		}
	})
	schema := SchemaName(siloedID)
	quotedSchema := pgx.Identifier{schema}.Sanitize()

	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	for _, tenantID := range []string{siloedID, pooledID} {
		err := tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
			pool,
			func(ctx context.Context, scope tenancy.Scope) error {
				if _, err := audit.TenantAppend(
					ctx,
					scope,
					"audit-policy-test",
					"retention.old.exported",
					tenantID,
					nil,
				); err != nil {
					return err
				}
				return (store.SIEMDelivery{}).Advance(ctx, scope, 1)
			},
		)
		if err != nil {
			t.Fatalf("seed audit-policy stream %s: %v", tenantID, err)
		}
	}
	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour)
	if _, err := pool.Exec(
		ctx,
		`UPDATE public.audit_events
		    SET created_at = $1
		  WHERE tenant_id = $2::uuid`,
		old,
		pooledID,
	); err != nil {
		t.Fatalf("backdate pooled audit-policy stream: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`UPDATE `+quotedSchema+`.audit_events
		    SET created_at = $1
		  WHERE tenant_id = $2::uuid`,
		old,
		siloedID,
	); err != nil {
		t.Fatalf("backdate silo audit-policy stream: %v", err)
	}

	const deploymentWindow = 365 * 24 * time.Hour
	life := tenantlife.New(
		pool,
		nil,
		nil,
		nil,
		func(ctx context.Context, actor, action, target string, data map[string]any) error {
			_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
			return err
		},
		"",
		log,
	).WithAuditRetentionMaximum(deploymentWindow)
	thirtyDays := 30
	if err := life.SetRetention(
		tenancy.WithTenant(ctx, tenancy.ID(siloedID)),
		tenantlife.RetentionPolicy{
			TenantID:           siloedID,
			AuditRetentionDays: &thirtyDays,
			UpdatedBy:          "silo-tenant-admin",
		},
		"silo-tenant-admin",
	); err != nil {
		t.Fatalf("set silo tenant audit policy: %v", err)
	}

	runner := audit.NewRetentionRunnerPG(
		pool,
		audit.RetentionPolicy{Window: deploymentWindow},
		nil,
		log,
	).WithTenantRetentionWindow(life.ProviderAuditRetentionWindowFor).
		WithTenantIDsForTest(func(context.Context) ([]string, error) {
			return []string{siloedID, pooledID}, nil
		}).
		WithNowForTest(func() time.Time { return now })
	summary, err := runner.Tick(ctx)
	if err != nil {
		t.Fatalf("run silo effective audit retention: %v", err)
	}
	if summary.TenantPruned != 1 || summary.TenantsChecked != 2 {
		t.Fatalf("silo effective retention summary = %+v, want silo-only prune", summary)
	}

	if got := countIn(t, pool, schema+".audit_events", siloedID); got != 2 {
		t.Fatalf("silo retained policy+receipt rows = %d, want 2", got)
	}
	if got := countIn(t, pool, "public.audit_events", siloedID); got != 0 {
		t.Fatalf("silo audit policy leaked into pooled table: %d", got)
	}
	if got := countIn(t, pool, "public.audit_events", pooledID); got != 1 {
		t.Fatalf("default-window pooled old rows = %d, want retained 1", got)
	}
	if got := countIn(t, pool, schema+".audit_events", pooledID); got != 0 {
		t.Fatalf("pooled audit row leaked into silo table: %d", got)
	}

	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(siloedID)),
		pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			var oldRows int64
			var receiptWindow string
			if err := scope.Q.QueryRow(
				ctx,
				`SELECT count(*) FROM audit_events
				  WHERE tenant_id = $1::uuid
				    AND action = 'retention.old.exported'`,
				siloedID,
			).Scan(&oldRows); err != nil {
				return err
			}
			if oldRows != 0 {
				return fmt.Errorf("silo old audit rows = %d, want pruned", oldRows)
			}
			if err := scope.Q.QueryRow(
				ctx,
				`SELECT data->>'retention_window'
				   FROM audit_events
				  WHERE tenant_id = $1::uuid AND action = $2`,
				siloedID,
				audit.RetentionPruneAction,
			).Scan(&receiptWindow); err != nil {
				return err
			}
			if receiptWindow != (30 * 24 * time.Hour).String() {
				return fmt.Errorf(
					"silo receipt window = %q, want %q",
					receiptWindow,
					(30 * 24 * time.Hour).String(),
				)
			}
			return audit.TenantVerify(ctx, scope)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(pooledID)),
		pool,
		audit.TenantVerify,
	)
	if err != nil {
		t.Fatalf("verify pooled default-window tenant: %v", err)
	}
}

func readTenantlifeBundle(t *testing.T, raw []byte) map[string]string {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("open tenantlife bundle gzip: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string]string{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read tenantlife bundle tar: %v", err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tenantlife bundle %s: %v", header.Name, err)
		}
		files[header.Name] = string(body)
	}
	return files
}
