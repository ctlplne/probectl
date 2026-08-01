// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package tenantlife

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/audit"
	"github.com/ctlplne/probectl/internal/store/flowstore"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// TestPooledTenantErasePostgresWriteFenceTwoTenant is the PostgreSQL slice of
// DATA-7683e96d. A write already inside the storage boundary must finish before
// the durable offboarding fence commits. Every later INSERT or UPDATE for that
// tenant is rejected by PostgreSQL itself, including table-owner writes, while
// a different active tenant remains writable.
func TestPooledTenantErasePostgresWriteFenceTwoTenant(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantA := mkTenant(t, pool, "pg-write-fence-a-"+stamp)
	tenantB := mkTenant(t, pool, "pg-write-fence-b-"+stamp)
	assertPublicTenantWriteFenceCoverage(ctx, t, pool)
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.results
			  WHERE tenant_id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants
			  WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
	})

	inflight, inflightPID, resultA := beginPooledResultWrite(
		ctx,
		t,
		pool,
		tenantA,
	)
	resultB, err := appendPooledResult(ctx, pool, tenantB)
	if err != nil {
		t.Fatalf("seed tenant B result: %v", err)
	}

	engine := New(
		pool,
		flowstore.NewMemory(),
		nil,
		nil,
		nil,
		"test backups",
		testLog(),
	)
	engine.appendProviderAuditTx = func(
		context.Context,
		tenancy.Querier,
		string,
		string,
		string,
		map[string]any,
	) (audit.Event, error) {
		return audit.Event{}, nil
	}

	fenceDone := make(chan error, 1)
	go func() {
		fenceDone <- engine.fenceTenantAuditWrites(
			ctx,
			tenantA,
			"privacy-admin",
		)
	}()

	waitForTenantWriteFenceWaiter(
		ctx,
		t,
		pool,
		inflightPID,
		fenceDone,
	)
	if err := inflight.Commit(ctx); err != nil {
		t.Fatalf("commit in-flight PostgreSQL write: %v", err)
	}
	if err := <-fenceDone; err != nil {
		t.Fatalf("establish PostgreSQL write fence: %v", err)
	}
	assertTenantStatus(ctx, t, pool, tenantA, "offboarding")

	if _, err := appendPooledResult(ctx, pool, tenantA); err == nil {
		t.Fatal("tenant A INSERT succeeded after the durable PostgreSQL fence")
	}
	if err := updatePooledResult(ctx, pool, tenantA, resultA); err == nil {
		t.Fatal("tenant A UPDATE succeeded after the durable PostgreSQL fence")
	}
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO public.results (tenant_id) VALUES ($1::uuid)`,
		tenantA,
	); err == nil {
		t.Fatal("table owner INSERT succeeded after the durable PostgreSQL fence")
	}

	if _, err := appendPooledResult(ctx, pool, tenantB); err != nil {
		t.Fatalf("tenant B INSERT was blocked by tenant A fence: %v", err)
	}
	if err := updatePooledResult(ctx, pool, tenantB, resultB); err != nil {
		t.Fatalf("tenant B UPDATE was blocked by tenant A fence: %v", err)
	}
}

func assertPublicTenantWriteFenceCoverage(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
) {
	t.Helper()
	rows, err := pool.Query(
		ctx,
		`SELECT c.relname,
		        EXISTS (
		            SELECT 1
		              FROM pg_catalog.pg_trigger AS trigger
		             WHERE trigger.tgrelid = c.oid
		               AND trigger.tgname = 'tenant_write_fence'
		               AND NOT trigger.tgisinternal
		        )
		   FROM pg_catalog.pg_class AS c
		   JOIN pg_catalog.pg_namespace AS n
		     ON n.oid = c.relnamespace
		   JOIN pg_catalog.pg_attribute AS a
		     ON a.attrelid = c.oid
		    AND a.attname = 'tenant_id'
		    AND NOT a.attisdropped
		  WHERE n.nspname = 'public'
		    AND c.relkind IN ('r', 'p')
		  ORDER BY c.relname`,
	)
	if err != nil {
		t.Fatalf("inventory public tenant write-fence coverage: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var table string
		var fenced bool
		if err := rows.Scan(&table, &fenced); err != nil {
			t.Fatal(err)
		}
		want := !tenancy.ProviderOwnedTable(table) &&
			table != "audit_events" &&
			table != "audit_subject_erasures"
		if fenced != want {
			t.Errorf(
				"public table %s tenant write fence = %t, want %t",
				table,
				fenced,
				want,
			)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate public tenant write-fence coverage: %v", err)
	}
}

func beginPooledResultWrite(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	tenantID string,
) (pgx.Tx, int32, string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
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
	var backendPID int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
		t.Fatal(err)
	}
	resultID := uuid.NewString()
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO public.results (id, tenant_id)
		 VALUES ($1::uuid, $2::uuid)`,
		resultID,
		tenantID,
	); err != nil {
		t.Fatalf("stage in-flight PostgreSQL result: %v", err)
	}
	return tx, backendPID, resultID
}

func waitForTenantWriteFenceWaiter(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	holderPID int32,
	fenceDone <-chan error,
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
			       FROM pg_stat_activity AS waiter
			      WHERE waiter.pid <> $1
			        AND $1 = ANY(pg_blocking_pids(waiter.pid))
			   )`,
			holderPID,
		).Scan(&waiting); err != nil {
			t.Fatalf("inspect tenant write-fence lock waiter: %v", err)
		}
		if waiting {
			return
		}
		select {
		case err := <-fenceDone:
			t.Fatalf(
				"PostgreSQL fence completed before the in-flight writer drained: %v",
				err,
			)
		case <-ctx.Done():
			t.Fatalf("PostgreSQL fence never waited for the in-flight writer: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func appendPooledResult(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID string,
) (string, error) {
	resultID := uuid.NewString()
	err := tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			_, err := scope.Q.Exec(
				ctx,
				`INSERT INTO public.results (id, tenant_id)
				 VALUES ($1::uuid, $2::uuid)`,
				resultID,
				tenantID,
			)
			return err
		},
	)
	return resultID, err
}

func updatePooledResult(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID, resultID string,
) error {
	return tenancy.InTenant(
		tenancy.WithTenant(ctx, tenancy.ID(tenantID)),
		pool,
		func(ctx context.Context, scope tenancy.Scope) error {
			tag, err := scope.Q.Exec(
				ctx,
				`UPDATE public.results
				    SET created_at = now()
				  WHERE id = $1::uuid`,
				resultID,
			)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return fmt.Errorf("updated %d rows, want 1", tag.RowsAffected())
			}
			return nil
		},
	)
}
