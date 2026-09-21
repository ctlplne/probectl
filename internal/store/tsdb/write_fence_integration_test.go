// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package tsdb

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

// TestTSDBEraseWriteFenceTwoTenant proves that the lease spans the actual TSDB
// backend mutation, rejects a mixed batch atomically, and remains effective
// beneath the production batching writer.
func TestTSDBEraseWriteFenceTwoTenant(t *testing.T) {
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
	tenantA := insertTSDBFenceTenant(ctx, t, pool, fmt.Sprintf("tsdb-fence-a-%d", stamp))
	tenantB := insertTSDBFenceTenant(ctx, t, pool, fmt.Sprintf("tsdb-fence-b-%d", stamp))
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
	})

	memory := NewMemory()
	blocking := &blockingTSDBWriter{
		Writer:   memory,
		tenantID: tenantA,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	writer := WithTenantWriteFence(
		blocking,
		tenancy.NewPostgresWriterFence(pool),
	)

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writer.Write(ctx, []Series{tsdbFenceSeries(tenantA, "in-flight")})
	}()
	select {
	case <-blocking.entered:
	case <-ctx.Done():
		t.Fatal("in-flight TSDB Write did not enter the backend")
	}

	fenceDone := make(chan error, 1)
	go func() {
		fenceDone <- commitTSDBEraseFence(ctx, pool, tenantA)
	}()
	select {
	case err := <-fenceDone:
		close(blocking.release)
		<-writeDone
		t.Fatalf("erasure fence did not drain the in-flight TSDB write: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(blocking.release)
	if err := <-writeDone; err != nil {
		t.Fatalf("in-flight TSDB Write: %v", err)
	}
	if err := <-fenceDone; err != nil {
		t.Fatalf("commit erasure fence: %v", err)
	}

	if err := writer.Write(
		ctx,
		[]Series{tsdbFenceSeries(tenantA, "post-fence")},
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf("tenant A Write after fence error = %v, want ErrTenantWritesFenced", err)
	}
	if err := writer.Write(
		ctx,
		[]Series{tsdbFenceSeries(tenantB, "tenant-b")},
	); err != nil {
		t.Fatalf("tenant B Write was blocked by tenant A fence: %v", err)
	}
	if err := writer.Write(ctx, []Series{
		tsdbFenceSeries(tenantA, "mixed-a"),
		tsdbFenceSeries(tenantB, "mixed-b"),
	}); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf("mixed A+B Write error = %v, want ErrTenantWritesFenced", err)
	}
	if got := memory.Query("probectl_tsdb_fence", map[string]string{
		TenantLabel: tenantB,
	}); len(got) != 1 {
		t.Fatalf("tenant B stored series = %d, want only its independent write", len(got))
	}

	batchedMemory := NewMemory()
	batched := NewBatchingWriter(batchedMemory, 1, time.Hour)
	batchedWriter := WithTenantWriteFence(
		batched,
		tenancy.NewPostgresWriterFence(pool),
	)
	t.Cleanup(func() { _ = batchedWriter.Close() })
	if err := batchedWriter.Write(
		ctx,
		[]Series{tsdbFenceSeries(tenantA, "batched-a")},
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf("batched tenant A Write error = %v, want ErrTenantWritesFenced", err)
	}
	if err := batchedWriter.Write(
		ctx,
		[]Series{tsdbFenceSeries(tenantB, "batched-b")},
	); err != nil {
		t.Fatalf("batched tenant B Write: %v", err)
	}
	if got := batchedMemory.Query("probectl_tsdb_fence", map[string]string{
		TenantLabel: tenantB,
	}); len(got) != 1 {
		t.Fatalf("batched tenant B stored series = %d, want 1", len(got))
	}
}

type blockingTSDBWriter struct {
	Writer
	tenantID string
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (w *blockingTSDBWriter) Write(ctx context.Context, series []Series) error {
	for i := range series {
		if series[i].Labels[TenantLabel] != w.tenantID {
			continue
		}
		w.once.Do(func() { close(w.entered) })
		select {
		case <-w.release:
		case <-ctx.Done():
			return ctx.Err()
		}
		break
	}
	return w.Writer.Write(ctx, series)
}

func commitTSDBEraseFence(
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
				return errors.New("tenant was not eligible for TSDB fence")
			}
			return nil
		},
	)
}

func insertTSDBFenceTenant(
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

func tsdbFenceSeries(tenantID, target string) Series {
	return Series{
		Metric: "probectl_tsdb_fence",
		Labels: map[string]string{
			TenantLabel: tenantID,
			"target":    target,
		},
		Value:      1,
		TimeMillis: time.Now().UnixMilli(),
	}
}
