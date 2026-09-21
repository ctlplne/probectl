// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

// TestFlowEraseWriteFenceTwoTenant proves DATA-51747686 at the flow storage
// boundary. An Insert already holding the shared writer lease must drain before
// the exclusive lifecycle fence commits. Later writes for that tenant fail
// before the backend, while a different active tenant remains writable.
func TestFlowEraseWriteFenceTwoTenant(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, testsupport.PostgresDSN())
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	testsupport.LockPostgresPublicCatalog(t, pool)

	stamp := time.Now().UTC().UnixNano()
	tenantA := insertFlowFenceTenant(ctx, t, pool, fmt.Sprintf("flow-fence-a-%d", stamp))
	tenantB := insertFlowFenceTenant(ctx, t, pool, fmt.Sprintf("flow-fence-b-%d", stamp))
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
	})
	memory := NewMemory()
	blocking := &blockingFlowInsert{
		Store:    memory,
		tenantID: tenantA,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	store := WithTenantWriteFence(
		blocking,
		tenancy.NewPostgresWriterFence(pool),
	)

	insertDone := make(chan error, 1)
	go func() {
		insertDone <- store.Insert(
			ctx,
			[]Row{{TenantID: tenantA, TS: time.Now()}},
		)
	}()
	select {
	case <-blocking.entered:
	case <-ctx.Done():
		t.Fatal("in-flight flow Insert did not enter the backend")
	}

	fenceDone := make(chan error, 1)
	go func() {
		fenceDone <- commitFlowEraseFence(ctx, pool, tenantA)
	}()
	select {
	case err := <-fenceDone:
		t.Fatalf("erasure fence did not drain the in-flight flow write: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(blocking.release)
	if err := <-insertDone; err != nil {
		t.Fatalf("in-flight flow Insert: %v", err)
	}
	if err := <-fenceDone; err != nil {
		t.Fatalf("commit erasure fence: %v", err)
	}

	if err := store.Insert(
		ctx,
		[]Row{{TenantID: tenantA, TS: time.Now().Add(time.Second)}},
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf(
			"tenant A flow Insert after fence error = %v, want ErrTenantWritesFenced",
			err,
		)
	}
	if err := store.Insert(
		ctx,
		[]Row{{TenantID: tenantB, TS: time.Now()}},
	); err != nil {
		t.Fatalf("tenant B flow Insert was blocked by tenant A fence: %v", err)
	}

	beforeMixed := memory.Len()
	if err := store.Insert(
		ctx,
		[]Row{
			{TenantID: tenantB, TS: time.Now().Add(time.Second)},
			{TenantID: tenantA, TS: time.Now().Add(2 * time.Second)},
		},
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf(
			"mixed fenced batch error = %v, want ErrTenantWritesFenced",
			err,
		)
	}
	if got := memory.Len(); got != beforeMixed {
		t.Fatalf(
			"mixed fenced batch partially entered backend: rows=%d, want %d",
			got,
			beforeMixed,
		)
	}
}

type blockingFlowInsert struct {
	Store
	tenantID string
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (s *blockingFlowInsert) Insert(ctx context.Context, rows []Row) error {
	for i := range rows {
		if rows[i].TenantID != s.tenantID {
			continue
		}
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		break
	}
	return s.Store.Insert(ctx, rows)
}

func commitFlowEraseFence(
	ctx context.Context,
	pool *pgxpool.Pool,
	tenantID string,
) error {
	return tenancy.InProvider(
		ctx,
		pool,
		func(ctx context.Context, q tenancy.Querier) error {
			if err := tenancy.LockTenantWrites(ctx, q, tenantID); err != nil {
				return err
			}
			tag, err := q.Exec(
				ctx,
				`UPDATE public.tenants
				    SET status = 'offboarding',
				        audit_write_fenced_at = now(),
				        updated_at = now()
				  WHERE id = $1::uuid
				    AND status = 'active'
				    AND audit_write_fenced_at IS NULL`,
				tenantID,
			)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				return errors.New("tenant was not eligible for flow fence")
			}
			return nil
		},
	)
}

func insertFlowFenceTenant(
	ctx context.Context,
	t *testing.T,
	pool *pgxpool.Pool,
	slug string,
) string {
	t.Helper()
	var tenantID string
	if err := pool.QueryRow(
		ctx,
		`INSERT INTO public.tenants (slug, name)
		 VALUES ($1, $1)
		 RETURNING id::text`,
		slug,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant %q: %v", slug, err)
	}
	return tenantID
}
