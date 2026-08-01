// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.

//go:build integration

package silo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/tenantlife"
	"github.com/ctlplne/probectl/internal/testsupport"
)

var errSubjectLockRowGone = errors.New("subject row was erased")

// TestSubjectErasureAuditLockOrderPooledAndSilo pauses erasure while it owns a
// subject row, then starts an audit-first mutation of that same row. The writer
// must wait on the tenant audit lock—not take the row lock and form the inverse
// audit↔row cycle. Tenant B proves the lock and erasure remain tenant-scoped.
func TestSubjectErasureAuditLockOrderPooledAndSilo(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	tenancy.SetRouter(NewRouter(pool, nil, 10*time.Millisecond))
	t.Cleanup(func() { tenancy.SetRouter(nil) })

	for _, model := range []tenancy.IsolationModel{
		tenancy.IsolationPooled,
		tenancy.IsolationSiloed,
	} {
		t.Run(string(model), func(t *testing.T) {
			runSubjectErasureAuditLockOrder(t, pool, log, model)
		})
	}
}

func runSubjectErasureAuditLockOrder(
	t *testing.T,
	pool *pgxpool.Pool,
	log *slog.Logger,
	model tenancy.IsolationModel,
) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	stamp := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantA := mkTenant(t, pool, "subject-lock-a-"+stamp, string(model), "")
	tenantB := mkTenant(t, pool, "subject-lock-b-"+stamp, string(model), "")
	t.Cleanup(func() {
		_, err := pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants
			  WHERE id = $1::uuid OR id = $2::uuid`,
			tenantA,
			tenantB,
		)
		if err != nil {
			t.Errorf("cleanup lock-order tenants: %v", err)
		}
	})

	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if model == tenancy.IsolationSiloed {
		for _, tenantID := range []string{tenantA, tenantB} {
			if err := provisioner.Provision(
				ctx,
				tenantID,
				"",
				tenancy.IsolationSiloed,
			); err != nil {
				t.Fatalf("provision subject-erasure silo %s: %v", tenantID, err)
			}
		}
		t.Cleanup(func() {
			for _, tenantID := range []string{tenantA, tenantB} {
				if err := provisioner.Teardown(
					context.Background(),
					tenantID,
					"",
					tenancy.IsolationSiloed,
				); err != nil {
					t.Errorf("teardown subject-erasure silo %s: %v", tenantID, err)
				}
			}
		})
	}

	subject := "lock-order-" + stamp + "@example.test"
	externalID := "lock-order-external-" + stamp
	userA := seedSubjectLockUser(t, pool, tenantA, subject, externalID)
	userB := seedSubjectLockUser(t, pool, tenantB, subject, "bystander-"+stamp)

	gateKey := time.Now().UnixNano() & 0x3fffffff
	gateTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin trigger gate: %v", err)
	}
	t.Cleanup(func() { _ = gateTx.Rollback(context.Background()) })
	if _, err := gateTx.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock($1::bigint)`,
		gateKey,
	); err != nil {
		t.Fatalf("hold trigger gate: %v", err)
	}

	usersTable := pgx.Identifier{"public", "users"}.Sanitize()
	if model == tenancy.IsolationSiloed {
		usersTable = pgx.Identifier{SchemaName(tenantA), "users"}.Sanitize()
	}
	functionName := pgx.Identifier{"public", "subject_lock_gate_" + stamp}.Sanitize()
	triggerName := pgx.Identifier{"subject_lock_gate_" + stamp}.Sanitize()
	if _, err := pool.Exec(
		ctx,
		`CREATE FUNCTION `+functionName+`() RETURNS trigger
		 LANGUAGE plpgsql AS $body$
		 BEGIN
		   PERFORM pg_advisory_xact_lock(`+fmt.Sprintf("%d", gateKey)+`::bigint);
		   RETURN OLD;
		 END
		 $body$`,
	); err != nil {
		t.Fatalf("create subject-erasure gate: %v", err)
	}
	if _, err := pool.Exec(
		ctx,
		`CREATE TRIGGER `+triggerName+`
		 BEFORE DELETE ON `+usersTable+`
		 FOR EACH ROW WHEN (OLD.id = '`+userA+`'::uuid)
		 EXECUTE FUNCTION `+functionName+`()`,
	); err != nil {
		t.Fatalf("attach subject-erasure gate: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(
			context.Background(),
			`DROP TRIGGER IF EXISTS `+triggerName+` ON `+usersTable,
		); err != nil {
			t.Errorf("drop subject-erasure gate: %v", err)
		}
		if _, err := pool.Exec(
			context.Background(),
			`DROP FUNCTION IF EXISTS `+functionName+`()`,
		); err != nil {
			t.Errorf("drop subject-erasure gate function: %v", err)
		}
	})

	eraseApp := "probectl-subject-erase-" + stamp
	mutateApp := "probectl-audited-mutate-" + stamp
	erasePool := subjectLockPool(t, eraseApp)
	mutatePool := subjectLockPool(t, mutateApp)
	t.Cleanup(erasePool.Close)
	t.Cleanup(mutatePool.Close)

	type eraseResult struct {
		report tenantlife.SubjectErasureReport
		err    error
	}
	eraseDone := make(chan eraseResult, 1)
	go func() {
		report, err := tenantlife.New(
			erasePool,
			nil,
			nil,
			nil,
			nil,
			"",
			log,
		).EraseSubject(
			ctx,
			tenantA,
			subject,
			"privacy-admin",
			"deterministic audit lock-order regression",
		)
		eraseDone <- eraseResult{report: report, err: err}
	}()
	if result, done := waitForSubjectAdvisoryLock(
		t,
		pool,
		eraseApp,
		"",
		eraseDone,
	); done {
		t.Fatalf("erasure missed row checkpoint: report=%+v err=%v", result.report, result.err)
	}

	mutateDone := make(chan error, 1)
	go func() {
		mutateDone <- tenancy.InTenant(
			tenancy.WithTenant(ctx, tenancy.ID(tenantA)),
			mutatePool,
			func(ctx context.Context, sc tenancy.Scope) error {
				if _, err := audit.TenantAppend(
					ctx,
					sc,
					"remediation-admin",
					"subject.lock_probe",
					userA,
					map[string]any{"reason": "concurrent same-row mutation"},
				); err != nil {
					return err
				}
				tag, err := sc.Q.Exec(
					ctx,
					`UPDATE users SET display_name = 'mutated'
					  WHERE tenant_id = $1::uuid AND id = $2::uuid`,
					tenantA,
					userA,
				)
				if err != nil {
					return err
				}
				if tag.RowsAffected() != 1 {
					return errSubjectLockRowGone
				}
				return nil
			},
		)
	}()
	if mutationErr, done := waitForSubjectAdvisoryLock(
		t,
		pool,
		mutateApp,
		eraseApp,
		mutateDone,
	); done {
		t.Fatalf("writer did not wait on tenant audit lock: %v", mutationErr)
	}

	if err := gateTx.Commit(ctx); err != nil {
		t.Fatalf("release subject-erasure gate: %v", err)
	}
	select {
	case erased := <-eraseDone:
		if erased.err != nil || !erased.report.Complete {
			t.Fatalf("subject erasure failed: report=%+v err=%v", erased.report, erased.err)
		}
	case <-ctx.Done():
		t.Fatalf("subject erasure did not finish: %v", ctx.Err())
	}
	select {
	case err := <-mutateDone:
		if !errors.Is(err, errSubjectLockRowGone) {
			t.Fatalf("concurrent writer error = %v, want erased-row result", err)
		}
	case <-ctx.Done():
		t.Fatalf("concurrent writer did not finish: %v", ctx.Err())
	}

	for _, alias := range []string{subject, externalID, userA} {
		assertSubjectLockCount(
			t,
			pool,
			subjectLockTable(model, tenantA, "audit_subject_erasures"),
			`tenant_id = $1::uuid AND subject_hash = $2`,
			tenantA,
			audit.SubjectErasureHash(tenantA, alias),
			1,
		)
	}
	assertSubjectLockCount(
		t,
		pool,
		subjectLockTable(model, tenantA, "users"),
		`tenant_id = $1::uuid AND id = $2::uuid`,
		tenantA,
		userA,
		0,
	)
	assertSubjectLockCount(
		t,
		pool,
		subjectLockTable(model, tenantA, "audit_events"),
		`tenant_id = $1::uuid
		   AND action = 'subject.lock_probe' AND target = $2`,
		tenantA,
		userA,
		0,
	)
	assertSubjectLockCount(
		t,
		pool,
		subjectLockTable(model, tenantB, "users"),
		`tenant_id = $1::uuid AND id = $2::uuid`,
		tenantB,
		userB,
		1,
	)
	var tenantBWrites int64
	err = tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantB)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			tag, err := sc.Q.Exec(
				ctx,
				`UPDATE users SET display_name = display_name
				  WHERE tenant_id = $1::uuid AND id = $2::uuid`,
				tenantB,
				userB,
			)
			tenantBWrites = tag.RowsAffected()
			return err
		},
	)
	if err != nil || tenantBWrites != 1 {
		t.Fatalf("tenant B write probe: rows=%d err=%v", tenantBWrites, err)
	}
}

func subjectLockPool(t *testing.T, applicationName string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(testsupport.PostgresDSN())
	if err != nil {
		t.Fatalf("parse PostgreSQL config: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = applicationName
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open PostgreSQL pool %q: %v", applicationName, err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	return pool
}

func waitForSubjectAdvisoryLock[T any](
	t *testing.T,
	pool *pgxpool.Pool,
	applicationName string,
	blockedByApplication string,
	done <-chan T,
) (T, bool) {
	t.Helper()
	var zero T
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case result := <-done:
			return result, true
		default:
		}
		var waiting bool
		err := pool.QueryRow(
			context.Background(),
			`SELECT EXISTS (
			   SELECT 1 FROM pg_stat_activity AS waiter
			    WHERE waiter.application_name = $1
			      AND waiter.wait_event_type = 'Lock'
			      AND lower(coalesce(waiter.wait_event, '')) = 'advisory'
			      AND (
			            $2::text = ''
			            OR EXISTS (
			                 SELECT 1 FROM pg_stat_activity AS blocker
			                  WHERE blocker.pid = ANY(pg_blocking_pids(waiter.pid))
			                    AND blocker.application_name = $2
			            )
			      )
			)`,
			applicationName,
			blockedByApplication,
		).Scan(&waiting)
		if err != nil {
			t.Fatalf("inspect PostgreSQL lock wait for %q: %v", applicationName, err)
		}
		if waiting {
			return zero, false
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("transaction %q never reached its advisory-lock wait", applicationName)
	return zero, false
}

func seedSubjectLockUser(
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID, subject, externalID string,
) string {
	t.Helper()
	var userID string
	err := tenancy.InTenant(
		tenancy.WithTenant(context.Background(), tenancy.ID(tenantID)),
		pool,
		func(ctx context.Context, sc tenancy.Scope) error {
			return sc.Q.QueryRow(
				ctx,
				`INSERT INTO users
				       (tenant_id, email, display_name, status, user_name,
				        external_id, attributes)
				 VALUES ($1::uuid, $2, 'Lock Order Subject', 'active', $2, $3,
				         jsonb_build_object('subject', $2::text))
				 RETURNING id::text`,
				tenantID,
				subject,
				externalID,
			).Scan(&userID)
		},
	)
	if err != nil {
		t.Fatalf("seed lock-order user for %s: %v", tenantID, err)
	}
	return userID
}

func subjectLockTable(
	model tenancy.IsolationModel,
	tenantID, table string,
) string {
	if model == tenancy.IsolationSiloed {
		return pgx.Identifier{SchemaName(tenantID), table}.Sanitize()
	}
	return pgx.Identifier{"public", table}.Sanitize()
}

func assertSubjectLockCount(
	t *testing.T,
	pool *pgxpool.Pool,
	table, predicate string,
	arg1, arg2 any,
	want int,
) {
	t.Helper()
	var got int
	if err := pool.QueryRow(
		context.Background(),
		`SELECT count(*) FROM `+table+` WHERE `+predicate,
		arg1,
		arg2,
	).Scan(&got); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if got != want {
		t.Fatalf("count %s = %d, want %d", table, got, want)
	}
}
