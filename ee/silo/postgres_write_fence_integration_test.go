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

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/tenantlife"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

type postgresWriteFenceIRLifecycle struct{}

func (postgresWriteFenceIRLifecycle) Plan(
	context.Context,
	string,
	string,
) (string, error) {
	return "postgres-write-fence-plan", nil
}

func (postgresWriteFenceIRLifecycle) Execute(
	context.Context,
	string,
	string,
	string,
) error {
	return nil
}

func (postgresWriteFenceIRLifecycle) RecordFailure(
	context.Context,
	string,
	string,
	string,
	string,
) error {
	return nil
}

// TestSiloTenantErasePostgresWriteFenceTwoTenant proves the PostgreSQL fence
// is physical-schema aware. A silo write already holding the shared storage
// lock drains before erasure, later writes to that silo fail closed, and a
// pooled bystander remains writable.
func TestSiloTenantErasePostgresWriteFenceTwoTenant(t *testing.T) {
	pool := itPool(t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	tenantA := mkTenant(t, pool, "silo-pg-fence-a-"+stamp, "siloed", "")
	tenantB := mkTenant(t, pool, "silo-pg-fence-b-"+stamp, "pooled", "")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	provisioner := NewProvisioner(pool, CHPlanes{}, nil, 0, log)
	if err := provisioner.Provision(
		ctx,
		tenantA,
		"",
		tenancy.IsolationSiloed,
	); err != nil {
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
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.results WHERE tenant_id = $1::uuid`,
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

	schema := SchemaName(tenantA)
	inflight, inflightPID, resultA := beginSiloResultWrite(
		t,
		ctx,
		pool,
		schema,
		tenantA,
	)
	resultB, err := appendSiloFenceResult(ctx, pool, tenantB)
	if err != nil {
		t.Fatalf("seed pooled tenant B result: %v", err)
	}

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
	engine := tenantlife.New(
		pool,
		flows,
		nil,
		nil,
		providerAudit,
		"test backups",
		log,
	).WithIRAttributionLifecycle(postgresWriteFenceIRLifecycle{})

	type eraseResult struct {
		att tenantlife.Attestation
		err error
	}
	eraseDone := make(chan eraseResult, 1)
	go func() {
		att, err := engine.Erase(
			ctx,
			tenantA,
			"silo-pg-fence-a-"+stamp,
			"privacy-admin",
		)
		eraseDone <- eraseResult{att: att, err: err}
	}()

	waitForSiloWriteFenceWaiter(
		t,
		ctx,
		pool,
		inflightPID,
		flows.entered,
	)
	if err := inflight.Commit(ctx); err != nil {
		t.Fatalf("commit in-flight silo result: %v", err)
	}
	select {
	case <-ctx.Done():
		t.Fatal("silo erasure did not reach its first post-fence store")
	case <-flows.entered:
	}
	assertSiloBarrierStatus(t, ctx, pool, tenantA, "offboarding")

	if _, err := appendSiloFenceResult(ctx, pool, tenantA); err == nil {
		t.Fatal("silo tenant A INSERT succeeded after the durable PostgreSQL fence")
	}
	if err := updateSiloFenceResult(ctx, pool, tenantA, resultA); err == nil {
		t.Fatal("silo tenant A UPDATE succeeded after the durable PostgreSQL fence")
	}
	if _, err := pool.Exec(
		ctx,
		`INSERT INTO `+pgx.Identifier{schema, "results"}.Sanitize()+
			` (tenant_id) VALUES ($1::uuid)`,
		tenantA,
	); err == nil {
		t.Fatal("silo table owner INSERT succeeded after the durable PostgreSQL fence")
	}
	if _, err := appendSiloFenceResult(ctx, pool, tenantB); err != nil {
		t.Fatalf("pooled tenant B INSERT was blocked by tenant A fence: %v", err)
	}
	if err := updateSiloFenceResult(ctx, pool, tenantB, resultB); err != nil {
		t.Fatalf("pooled tenant B UPDATE was blocked by tenant A fence: %v", err)
	}

	close(flows.release)
	var erased eraseResult
	select {
	case <-ctx.Done():
		t.Fatal("silo erasure did not finish after releasing its first store")
	case erased = <-eraseDone:
	}
	if erased.err != nil {
		t.Fatalf("silo erase: %v; attestation=%+v", erased.err, erased.att)
	}
	if !erased.att.Complete {
		t.Fatalf("silo erase attestation incomplete: %+v", erased.att.Stores)
	}
	assertSiloBarrierStatus(t, ctx, pool, tenantA, "deleted")
	if _, err := appendSiloFenceResult(ctx, pool, tenantA); err == nil {
		t.Fatal("silo tenant A INSERT succeeded after deletion")
	}
	if _, err := appendSiloFenceResult(ctx, pool, tenantB); err != nil {
		t.Fatalf("pooled tenant B was not writable after tenant A deletion: %v", err)
	}
}

func beginSiloResultWrite(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	schema, tenantID string,
) (pgx.Tx, int32, string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
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
	var backendPID int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
		t.Fatal(err)
	}
	resultID := uuid.NewString()
	if _, err := tx.Exec(
		ctx,
		`INSERT INTO results (id, tenant_id)
		 VALUES ($1::uuid, $2::uuid)`,
		resultID,
		tenantID,
	); err != nil {
		t.Fatalf("stage in-flight silo result: %v", err)
	}
	return tx, backendPID, resultID
}

func waitForSiloWriteFenceWaiter(
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
			       FROM pg_stat_activity AS waiter
			      WHERE waiter.pid <> $1
			        AND $1 = ANY(pg_blocking_pids(waiter.pid))
			   )`,
			holderPID,
		).Scan(&waiting); err != nil {
			t.Fatalf("inspect silo tenant write-fence waiter: %v", err)
		}
		if waiting {
			return
		}
		select {
		case <-storeEntered:
			t.Fatal("silo erasure touched data before its in-flight writer drained")
		case <-ctx.Done():
			t.Fatalf("silo erasure never waited for its in-flight writer: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func appendSiloFenceResult(
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
				`INSERT INTO results (id, tenant_id)
				 VALUES ($1::uuid, $2::uuid)`,
				resultID,
				tenantID,
			)
			return err
		},
	)
	return resultID, err
}

func updateSiloFenceResult(
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
				`UPDATE results
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
