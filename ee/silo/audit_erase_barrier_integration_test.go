// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

//go:build integration

package silo

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

type blockingSiloAuditBarrierFlowStore struct {
	flowstore.Store
	entered chan struct{}
	release chan struct{}
}

func (s *blockingSiloAuditBarrierFlowStore) DeleteTenant(
	ctx context.Context,
	tenantID string,
) (int64, error) {
	select {
	case <-s.entered:
	default:
		close(s.entered)
	}
	select {
	case <-ctx.Done():
		return -1, ctx.Err()
	case <-s.release:
		return s.Store.DeleteTenant(ctx, tenantID)
	}
}

// TestSiloTenantEraseConcurrentAuditBarrier proves the DATA-6814b317 barrier
// is physical-storage scoped: a siloed tenant cannot race either append-only
// table through full erasure, while a pooled bystander remains writable.
func TestSiloTenantEraseConcurrentAuditBarrier(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantA := mkTenant(t, pool, "silo-audit-erase-a-"+stamp, "siloed", "")
	tenantB := mkTenant(t, pool, "silo-audit-erase-b-"+stamp, "pooled", "")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := provisioner.Provision(ctx, tenantA, "", tenancy.IsolationSiloed); err != nil {
		t.Fatalf("provision silo: %v", err)
	}
	router := NewRouter(pool, nil, time.Second)
	tenancy.SetRouter(router)
	t.Cleanup(func() {
		tenancy.SetRouter(nil)
		if err := provisioner.Teardown(
			context.Background(),
			tenantA,
			"",
			tenancy.IsolationSiloed,
		); err != nil {
			t.Errorf("cleanup silo: %v", err)
		}
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		); err != nil {
			t.Errorf("cleanup audit barrier tenants: %v", err)
		}
	})

	schema := SchemaName(tenantA)
	inflight, inflightPID := beginSiloSubjectErasure(
		t,
		ctx,
		pool,
		schema,
		tenantA,
	)
	flows := &blockingSiloAuditBarrierFlowStore{
		Store:   flowstore.NewMemory(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	t.Cleanup(func() {
		select {
		case <-flows.release:
		default:
			close(flows.release)
		}
	})
	providerAudit := func(
		ctx context.Context,
		actor, action, target string,
		data map[string]any,
	) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	engine := tenantlife.New(
		pool,
		flows,
		nil,
		nil,
		providerAudit,
		"test backups",
		log,
	)

	type eraseResult struct {
		att tenantlife.Attestation
		err error
	}
	eraseDone := make(chan eraseResult, 1)
	go func() {
		att, err := engine.Erase(
			ctx,
			tenantA,
			"silo-audit-erase-a-"+stamp,
			"privacy-admin",
		)
		eraseDone <- eraseResult{att: att, err: err}
	}()

	waitForSiloTenantAuditLockWaiter(
		t,
		ctx,
		pool,
		inflightPID,
		flows.entered,
	)
	if err := inflight.Commit(ctx); err != nil {
		t.Fatalf("commit in-flight silo subject erasure: %v", err)
	}

	select {
	case <-ctx.Done():
		t.Fatal("silo erase did not reach the first post-fence store")
	case <-flows.entered:
	}
	assertSiloBarrierStatus(t, ctx, pool, tenantA, "offboarding")

	assertSiloRawAuditWritesDenied(t, ctx, pool, tenantA, "post-fence-a")
	assertSiloOwnerAuditWritesDenied(t, ctx, pool, schema, tenantA)
	assertSiloRawAuditWritesAllowed(t, ctx, pool, tenantB, "active-b")

	if err := setSiloTenantStatusAsProvider(
		ctx,
		pool,
		tenantB,
		"suspended",
	); err != nil {
		t.Fatalf("suspend eligible pooled tenant B: %v", err)
	}
	assertSiloBarrierStatus(t, ctx, pool, tenantB, "suspended")
	assertSiloRawAuditWritesAllowed(t, ctx, pool, tenantB, "suspended-b")

	// The write-once registry fence must reject a stale provider replica that
	// tries to reopen the siloed tenant while erasure is paused.
	if err := setSiloTenantStatusAsProvider(
		ctx,
		pool,
		tenantA,
		"active",
	); err == nil {
		t.Fatal("provider reopened a siloed tenant after the durable erasure fence")
	}
	assertSiloBarrierStatus(t, ctx, pool, tenantA, "offboarding")
	assertSiloRawAuditWritesDenied(t, ctx, pool, tenantA, "forced-active-a")

	close(flows.release)
	var result eraseResult
	select {
	case <-ctx.Done():
		t.Fatal("silo erase did not finish after releasing the first store")
	case result = <-eraseDone:
	}
	if result.err != nil {
		t.Fatalf("silo erase: %v; attestation=%+v", result.err, result.att)
	}
	if !result.att.Complete {
		t.Fatalf("silo erase attestation incomplete: %+v", result.att.Stores)
	}
	assertSiloBarrierStatus(t, ctx, pool, tenantA, "deleted")
	assertSiloAuditBarrierCounts(t, ctx, pool, schema, tenantA, 0, 0)
	assertSiloAuditBarrierCounts(t, ctx, pool, "public", tenantB, 2, 2)

	assertSiloRawAuditWritesDenied(t, ctx, pool, tenantA, "post-delete-a")
	assertSiloRawAuditWritesAllowed(t, ctx, pool, tenantB, "post-delete-b")
	assertSiloAuditBarrierCounts(t, ctx, pool, "public", tenantB, 3, 3)
}

func beginSiloSubjectErasure(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	schema, tenantID string,
) (pgx.Tx, int32) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	var backendPID int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		ctx,
		"SET LOCAL search_path TO "+pgx.Identifier{schema}.Sanitize()+", public",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+tenancy.AppRole); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(
		ctx,
		`SELECT set_config('probectl.tenant_id', $1, true)`,
		tenantID,
	); err != nil {
		t.Fatal(err)
	}
	hash := audit.SubjectErasureHash(tenantID, "inflight@example.test")
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO audit_subject_erasures (tenant_id, subject_hash)
		 VALUES ($1::uuid, $2)`,
		tenantID,
		hash,
	); err != nil {
		t.Fatalf("stage rolling-old silo subject projection: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO audit_events
		    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1::uuid, 1, 'old-silo-writer', $2, $3, $4::jsonb, '', $5)`,
		tenantID,
		audit.SubjectErasureAction,
		"subject:"+hash[:12],
		fmt.Sprintf(`{"subject_hash":%q}`, hash),
		"rolling-old-silo-fixture",
	); err != nil {
		t.Fatalf("stage rolling-old silo audit event: %v", err)
	}
	return tx, backendPID
}

func waitForSiloTenantAuditLockWaiter(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	holderPID int32,
	storeEntered <-chan struct{},
) {
	t.Helper()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		if err := pool.QueryRow(
			ctx,
			`SELECT EXISTS (
			     SELECT 1
			       FROM pg_locks AS holder
			       JOIN pg_locks AS waiter
			         ON waiter.locktype = holder.locktype
			        AND waiter.database IS NOT DISTINCT FROM holder.database
			        AND waiter.classid IS NOT DISTINCT FROM holder.classid
			        AND waiter.objid IS NOT DISTINCT FROM holder.objid
			        AND waiter.objsubid IS NOT DISTINCT FROM holder.objsubid
			      WHERE holder.pid = $1
			        AND holder.locktype = 'advisory'
			        AND holder.granted
			        AND waiter.pid <> holder.pid
			        AND NOT waiter.granted
			   )`,
			holderPID,
		).Scan(&waiting); err != nil {
			t.Fatalf("inspect silo tenant audit advisory lock waiters: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-storeEntered:
			t.Fatal("silo erase crossed into data deletion before waiting on the in-flight audit writer")
		case <-ctx.Done():
			t.Fatalf("silo erase never waited on the tenant audit advisory lock: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func appendRoutedRawSubjectErasure(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, marker string,
) error {
	return tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			hash := audit.SubjectErasureHash(
				tenantID,
				marker+"@example.test",
			)
			_, err := scope.Q.Exec(
				ctx,
				`INSERT INTO audit_subject_erasures (tenant_id, subject_hash)
				 VALUES ($1::uuid, $2)`,
				tenantID,
				hash,
			)
			return err
		},
	)
}

func appendRoutedRawAuditEvent(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, marker string,
) error {
	return tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			var seq int64
			if err := scope.Q.QueryRow(
				ctx,
				`SELECT COALESCE(max(seq), 0) + 1 FROM audit_events`,
			).Scan(&seq); err != nil {
				return err
			}
			_, err := scope.Q.Exec(
				ctx,
				`INSERT INTO audit_events
				    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
				 VALUES ($1::uuid, $2, 'rolling-old-silo-writer',
				         'test.audit_barrier', $3, $4::jsonb, '', $5)`,
				tenantID,
				seq,
				marker,
				fmt.Sprintf(`{"marker":%q}`, marker),
				fmt.Sprintf("rolling-old-silo-fixture-%s-%d", marker, seq),
			)
			return err
		},
	)
}

func assertSiloRawAuditWritesDenied(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, marker string,
) {
	t.Helper()
	if err := appendRoutedRawAuditEvent(
		ctx,
		pool,
		tenantID,
		marker+"-event",
	); err == nil {
		t.Errorf("tenant %s raw audit event insert succeeded across the durable fence", tenantID)
	}
	if err := appendRoutedRawSubjectErasure(
		ctx,
		pool,
		tenantID,
		marker+"-projection",
	); err == nil {
		t.Errorf("tenant %s raw subject-erasure insert succeeded across the durable fence", tenantID)
	}
}

func assertSiloRawAuditWritesAllowed(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, marker string,
) {
	t.Helper()
	if err := appendRoutedRawAuditEvent(
		ctx,
		pool,
		tenantID,
		marker+"-event",
	); err != nil {
		t.Fatalf("tenant %s eligible raw audit event insert: %v", tenantID, err)
	}
	if err := appendRoutedRawSubjectErasure(
		ctx,
		pool,
		tenantID,
		marker+"-projection",
	); err != nil {
		t.Fatalf("tenant %s eligible raw subject-erasure insert: %v", tenantID, err)
	}
}

func assertSiloOwnerAuditWritesDenied(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	schema, tenantID string,
) {
	t.Helper()
	events := pgx.Identifier{schema, "audit_events"}.Sanitize()
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO `+events+`
		    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1::uuid, 9000001, 'fixture-owner',
		         'test.audit_barrier', 'owner-event', '{}'::jsonb, '',
		         'owner-event-fixture')`,
		tenantID,
	); err == nil {
		t.Errorf("silo table owner inserted an audit event across the durable fence")
	}
	projections := pgx.Identifier{
		schema,
		"audit_subject_erasures",
	}.Sanitize()
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO `+projections+` (tenant_id, subject_hash)
		 VALUES ($1::uuid, 'owner-projection-fixture')`,
		tenantID,
	); err == nil {
		t.Errorf("silo table owner inserted a subject-erasure row across the durable fence")
	}
}

func setSiloTenantStatusAsProvider(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, status string,
) error {
	return tenancy.InProvider(
		ctx,
		pool,
		func(ctx context.Context, q tenancy.Querier) error {
			tag, err := q.Exec(
				ctx,
				`UPDATE public.tenants
				    SET status = $2,
				        updated_at = now()
				  WHERE id = $1::uuid`,
				tenantID,
				status,
			)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf(
					"tenant status update affected %d rows",
					tag.RowsAffected(),
				)
			}
			return nil
		},
	)
}

func assertSiloBarrierStatus(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, want string,
) {
	t.Helper()
	var got string
	if err := pool.QueryRow(
		ctx,
		`SELECT status FROM public.tenants WHERE id = $1::uuid`,
		tenantID,
	).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("tenant %s status = %q, want %q", tenantID, got, want)
	}
}

func assertSiloAuditBarrierCounts(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	schema, tenantID string,
	wantEvents, wantProjections int,
) {
	t.Helper()
	for table, want := range map[string]int{
		"audit_events":           wantEvents,
		"audit_subject_erasures": wantProjections,
	} {
		var got int
		if err := pool.QueryRow(
			ctx,
			`SELECT count(*) FROM `+pgx.Identifier{schema, table}.Sanitize()+
				` WHERE tenant_id = $1::uuid`,
			tenantID,
		).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("%s.%s tenant %s rows = %d, want %d", schema, table, tenantID, got, want)
		}
	}
}
