// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package pathstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/path"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// TestPathEraseWriteFenceTwoTenant proves the shared tenant-writer lease at
// the path backend boundary. It also proves that the production write-behind
// wrapper fences its actual flush, not merely the enqueue call.
func TestPathEraseWriteFenceTwoTenant(t *testing.T) {
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
	tenantA := insertPathFenceTenant(t, ctx, pool, fmt.Sprintf("path-fence-a-%d", stamp))
	tenantB := insertPathFenceTenant(t, ctx, pool, fmt.Sprintf("path-fence-b-%d", stamp))
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
	})

	memory := NewMemory()
	blocking := &blockingPathStore{
		Store:    memory,
		tenantID: tenantA,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	store := WithTenantWriteFence(
		blocking,
		tenancy.NewPostgresWriterFence(pool),
	)

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- store.Save(ctx, tenantA, pathFencePath("198.51.100.10"))
	}()
	select {
	case <-blocking.entered:
	case <-ctx.Done():
		t.Fatal("in-flight path Save did not enter the backend")
	}

	fenceDone := make(chan error, 1)
	go func() {
		fenceDone <- commitPathEraseFence(ctx, pool, tenantA)
	}()
	select {
	case err := <-fenceDone:
		close(blocking.release)
		<-writeDone
		t.Fatalf("erasure fence did not drain the in-flight path write: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(blocking.release)
	if err := <-writeDone; err != nil {
		t.Fatalf("in-flight path Save: %v", err)
	}
	if err := <-fenceDone; err != nil {
		t.Fatalf("commit erasure fence: %v", err)
	}

	if err := store.Save(
		ctx,
		tenantA,
		pathFencePath("198.51.100.11"),
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf("tenant A Save after fence error = %v, want ErrTenantWritesFenced", err)
	}
	if err := store.Save(
		ctx,
		tenantB,
		pathFencePath("203.0.113.20"),
	); err != nil {
		t.Fatalf("tenant B Save was blocked by tenant A fence: %v", err)
	}
	if got := len(memory.ForTenant(tenantB)); got != 1 {
		t.Fatalf("tenant B paths = %d, want 1", got)
	}

	batchedMemory := NewMemory()
	batched := NewBatchingSaver(
		batchedMemory,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		time.Hour,
		32,
	)
	batchedStore := WithTenantWriteFence(
		batched,
		tenancy.NewPostgresWriterFence(pool),
	)
	if err := batchedStore.Save(
		ctx,
		tenantA,
		pathFencePath("198.51.100.12"),
	); err != nil {
		t.Fatalf("queue post-fence tenant A path: %v", err)
	}
	batched.Flush(ctx)
	if got := len(batchedMemory.ForTenant(tenantA)); got != 0 {
		t.Fatalf("post-fence batched tenant A paths persisted = %d, want 0", got)
	}
	if got := batched.Lost(); got != 1 {
		t.Fatalf("rejected tenant A batched paths recorded lost = %d, want 1", got)
	}
	if err := batchedStore.Save(
		ctx,
		tenantB,
		pathFencePath("203.0.113.21"),
	); err != nil {
		t.Fatalf("queue tenant B batched path: %v", err)
	}
	batched.Flush(ctx)
	if got := len(batchedMemory.ForTenant(tenantB)); got != 1 {
		t.Fatalf("tenant B batched paths = %d, want 1", got)
	}
}

type blockingPathStore struct {
	Store
	tenantID string
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (s *blockingPathStore) Save(
	ctx context.Context,
	tenantID string,
	p *path.Path,
) error {
	if tenantID == s.tenantID {
		s.once.Do(func() { close(s.entered) })
		select {
		case <-s.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.Store.Save(ctx, tenantID, p)
}

func commitPathEraseFence(
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
				return errors.New("tenant was not eligible for path fence")
			}
			return nil
		},
	)
}

func insertPathFenceTenant(
	t *testing.T,
	ctx context.Context,
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

func pathFencePath(target string) *path.Path {
	return &path.Path{Target: target}
}
