// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package tenantlife

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

type blockingAuditBarrierFlowStore struct {
	flowstore.Store
	entered chan struct{}
	release chan struct{}
}

func (s *blockingAuditBarrierFlowStore) DeleteTenant(
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

// TestPooledTenantEraseConcurrentAuditBarrier is the pooled fail-before /
// pass-after regression for DATA-6814b317.
//
// An old writer holds the canonical audit lock with both an audit event and its
// subject-erasure projection uncommitted. Erase must wait for that writer,
// durably fence the tenant before touching another store, reject every later
// append, and atomically delete+verify both append-only tables. Tenant B stays
// writable throughout.
func TestPooledTenantEraseConcurrentAuditBarrier(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantA := mkTenant(t, pool, "audit-erase-barrier-a-"+stamp)
	tenantB := mkTenant(t, pool, "audit-erase-barrier-b-"+stamp)
	t.Cleanup(func() {
		if _, err := pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		); err != nil {
			t.Errorf("cleanup audit barrier tenants: %v", err)
		}
	})

	inflight, inflightPID := beginPooledSubjectErasure(t, ctx, pool, tenantA)
	flows := &blockingAuditBarrierFlowStore{
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
	engine := New(pool, flows, nil, nil, providerAudit, "test backups", testLog())

	type eraseResult struct {
		att Attestation
		err error
	}
	eraseDone := make(chan eraseResult, 1)
	go func() {
		att, err := engine.Erase(ctx, tenantA, "audit-erase-barrier-a-"+stamp, "privacy-admin")
		eraseDone <- eraseResult{att: att, err: err}
	}()

	waitForTenantAuditLockWaiter(
		t,
		ctx,
		pool,
		inflightPID,
		flows.entered,
	)
	if err := inflight.Commit(ctx); err != nil {
		t.Fatalf("commit in-flight subject erasure: %v", err)
	}

	select {
	case <-ctx.Done():
		t.Fatal("erase did not reach the first post-fence store")
	case <-flows.entered:
	}
	assertTenantStatus(t, ctx, pool, tenantA, "offboarding")

	assertRawAuditWritesDenied(t, ctx, pool, tenantA, "post-fence-a")
	assertOwnerAuditWritesDenied(t, ctx, pool, "public", tenantA)
	assertRawAuditWritesAllowed(t, ctx, pool, tenantB, "active-b")

	if err := setTenantStatusAsProvider(ctx, pool, tenantB, "suspended"); err != nil {
		t.Fatalf("suspend eligible tenant B: %v", err)
	}
	assertTenantStatus(t, ctx, pool, tenantB, "suspended")
	assertRawAuditWritesAllowed(t, ctx, pool, tenantB, "suspended-b")

	// A provider/admin status write must not be able to erase the durable
	// lifecycle barrier. This simulates a stale or compromised control-plane
	// replica trying to reopen the registry while erasure is paused.
	if err := setTenantStatusAsProvider(ctx, pool, tenantA, "active"); err == nil {
		t.Fatal("provider reopened a tenant after the durable erasure fence")
	}
	assertTenantStatus(t, ctx, pool, tenantA, "offboarding")
	assertRawAuditWritesDenied(t, ctx, pool, tenantA, "forced-active-a")

	close(flows.release)
	var result eraseResult
	select {
	case <-ctx.Done():
		t.Fatal("erase did not finish after releasing the first store")
	case result = <-eraseDone:
	}
	if result.err != nil {
		t.Fatalf("erase: %v; attestation=%+v", result.err, result.att)
	}
	if !result.att.Complete {
		t.Fatalf("erase attestation incomplete: %+v", result.att.Stores)
	}
	assertTenantStatus(t, ctx, pool, tenantA, "deleted")
	assertAuditBarrierCounts(t, ctx, pool, "public", tenantA, 0, 0)
	assertAuditBarrierCounts(t, ctx, pool, "public", tenantB, 2, 2)

	assertRawAuditWritesDenied(t, ctx, pool, tenantA, "post-delete-a")
	assertRawAuditWritesAllowed(t, ctx, pool, tenantB, "post-delete-b")
	assertAuditBarrierCounts(t, ctx, pool, "public", tenantB, 3, 3)
}

func TestPooledTenantEraseFenceAuditFailureRollsBack(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID := mkTenant(t, pool, "audit-fence-rollback-"+stamp)
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id = $1::uuid`,
			tenantID,
		)
	})

	flows := &blockingAuditBarrierFlowStore{
		Store:   flowstore.NewMemory(),
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	close(flows.release)
	engine := New(pool, flows, nil, nil, nil, "test backups", testLog())
	engine.appendProviderAuditTx = func(
		context.Context,
		tenancy.Querier,
		string,
		string,
		string,
		map[string]any,
	) (audit.Event, error) {
		return audit.Event{}, errors.New("forced provider audit failure")
	}

	if _, err := engine.Erase(
		ctx,
		tenantID,
		"audit-fence-rollback-"+stamp,
		"privacy-admin",
	); err == nil {
		t.Fatal("erase succeeded when its atomic fence audit failed")
	}
	select {
	case <-flows.entered:
		t.Fatal("erase touched a data store after its fence audit rolled back")
	default:
	}
	assertTenantStatus(t, ctx, pool, tenantID, "active")
	assertTenantFence(t, ctx, pool, tenantID, false)
	assertRawAuditWritesAllowed(t, ctx, pool, tenantID, "rollback-writable")
}

func TestPooledTenantEraseFinalAuditFailureIsRetryable(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantID := mkTenant(t, pool, "audit-finalize-retry-"+stamp)
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id = $1::uuid`,
			tenantID,
		)
	})

	providerAudit := func(
		ctx context.Context,
		actor, action, target string,
		data map[string]any,
	) error {
		_, err := audit.ProviderAppend(
			ctx,
			pool,
			actor,
			action,
			target,
			data,
		)
		return err
	}
	engine := New(
		pool,
		flowstore.NewMemory(),
		nil,
		nil,
		providerAudit,
		"test backups",
		testLog(),
	)
	engine.appendProviderAuditTx = func(
		ctx context.Context,
		q tenancy.Querier,
		actor, action, target string,
		data map[string]any,
	) (audit.Event, error) {
		if action == "lifecycle.erase" {
			return audit.Event{}, errors.New("forced final audit failure")
		}
		return audit.ProviderAppendTx(
			ctx,
			q,
			actor,
			action,
			target,
			data,
		)
	}

	first, err := engine.Erase(
		ctx,
		tenantID,
		"audit-finalize-retry-"+stamp,
		"privacy-admin",
	)
	if err == nil {
		t.Fatalf("erase succeeded despite final audit failure: %+v", first)
	}
	assertTenantStatus(t, ctx, pool, tenantID, "offboarding")
	assertTenantFence(t, ctx, pool, tenantID, true)
	assertRawAuditWritesDenied(t, ctx, pool, tenantID, "retry-fenced")

	engine.appendProviderAuditTx = audit.ProviderAppendTx
	second, err := engine.Erase(
		ctx,
		tenantID,
		"audit-finalize-retry-"+stamp,
		"privacy-admin",
	)
	if err != nil {
		t.Fatalf("retry erased fenced tenant: %v; attestation=%+v", err, second)
	}
	if !second.Complete {
		t.Fatalf("retry attestation incomplete: %+v", second.Stores)
	}
	assertTenantStatus(t, ctx, pool, tenantID, "deleted")
	assertTenantFence(t, ctx, pool, tenantID, true)
}

func beginPooledSubjectErasure(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID string,
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
		t.Fatalf("stage rolling-old subject projection: %v", err)
	}
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO audit_events
		    (tenant_id, seq, actor, action, target, data, prev_hash, hash)
		 VALUES ($1::uuid, 1, 'old-writer', $2, $3, $4::jsonb, '', $5)`,
		tenantID,
		audit.SubjectErasureAction,
		"subject:"+hash[:12],
		fmt.Sprintf(`{"subject_hash":%q}`, hash),
		"rolling-old-fixture",
	); err != nil {
		t.Fatalf("stage rolling-old audit event: %v", err)
	}
	return tx, backendPID
}

func waitForTenantAuditLockWaiter(
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
			t.Fatalf("inspect tenant audit advisory lock waiters: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-storeEntered:
			t.Fatal("erase crossed into data deletion before waiting on the in-flight audit writer")
		case <-ctx.Done():
			t.Fatalf("erase never waited on the tenant audit advisory lock: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func appendRawSubjectErasure(
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

func appendRawAuditEvent(
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
				 VALUES ($1::uuid, $2, 'rolling-old-writer',
				         'test.audit_barrier', $3, $4::jsonb, '', $5)`,
				tenantID,
				seq,
				marker,
				fmt.Sprintf(`{"marker":%q}`, marker),
				fmt.Sprintf("rolling-old-fixture-%s-%d", marker, seq),
			)
			return err
		},
	)
}

func assertRawAuditWritesDenied(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, marker string,
) {
	t.Helper()
	if err := appendRawAuditEvent(
		ctx,
		pool,
		tenantID,
		marker+"-event",
	); err == nil {
		t.Errorf("tenant %s raw audit event insert succeeded across the durable fence", tenantID)
	}
	if err := appendRawSubjectErasure(
		ctx,
		pool,
		tenantID,
		marker+"-projection",
	); err == nil {
		t.Errorf("tenant %s raw subject-erasure insert succeeded across the durable fence", tenantID)
	}
}

func assertRawAuditWritesAllowed(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, marker string,
) {
	t.Helper()
	if err := appendRawAuditEvent(
		ctx,
		pool,
		tenantID,
		marker+"-event",
	); err != nil {
		t.Fatalf("tenant %s eligible raw audit event insert: %v", tenantID, err)
	}
	if err := appendRawSubjectErasure(
		ctx,
		pool,
		tenantID,
		marker+"-projection",
	); err != nil {
		t.Fatalf("tenant %s eligible raw subject-erasure insert: %v", tenantID, err)
	}
}

func assertOwnerAuditWritesDenied(
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
		t.Errorf("table owner inserted an audit event across the durable fence")
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
		t.Errorf("table owner inserted a subject-erasure row across the durable fence")
	}
}

func setTenantStatusAsProvider(
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
				return fmt.Errorf("tenant status update affected %d rows", tag.RowsAffected())
			}
			return nil
		},
	)
}

func assertTenantFence(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID string,
	want bool,
) {
	t.Helper()
	var got bool
	if err := pool.QueryRow(
		ctx,
		`SELECT audit_write_fenced_at IS NOT NULL
		   FROM public.tenants
		  WHERE id = $1::uuid`,
		tenantID,
	).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("tenant %s durable audit fence = %t, want %t", tenantID, got, want)
	}
}

func assertTenantStatus(
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

func assertAuditBarrierCounts(
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
