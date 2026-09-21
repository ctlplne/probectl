// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package otelstore

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

// TestOTLPEraseWriteFenceTwoTenant proves the shared tenant-writer lease at
// the OTLP storage boundary for both spans and logs. An in-flight tenant-A
// span drains before fencing; all later A or mixed A+B writes fail before the
// backend, while tenant B remains writable.
func TestOTLPEraseWriteFenceTwoTenant(t *testing.T) {
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
	tenantA := insertOTLPFenceTenant(ctx, t, pool, fmt.Sprintf("otlp-fence-a-%d", stamp))
	tenantB := insertOTLPFenceTenant(ctx, t, pool, fmt.Sprintf("otlp-fence-b-%d", stamp))
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
	})

	memory := NewMemory()
	blocking := &blockingOTLPStore{
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
		writeDone <- store.WriteSpans(
			ctx,
			[]Span{otlpFenceSpan(tenantA, time.Now())},
		)
	}()
	select {
	case <-blocking.entered:
	case <-ctx.Done():
		t.Fatal("in-flight OTLP span write did not enter the backend")
	}

	fenceDone := make(chan error, 1)
	go func() {
		fenceDone <- commitOTLPEraseFence(ctx, pool, tenantA)
	}()
	select {
	case err := <-fenceDone:
		close(blocking.release)
		<-writeDone
		t.Fatalf("erasure fence did not drain the in-flight OTLP write: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(blocking.release)
	if err := <-writeDone; err != nil {
		t.Fatalf("in-flight OTLP span write: %v", err)
	}
	if err := <-fenceDone; err != nil {
		t.Fatalf("commit erasure fence: %v", err)
	}

	if err := store.WriteSpans(
		ctx,
		[]Span{otlpFenceSpan(tenantA, time.Now().Add(time.Second))},
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf(
			"tenant A span write after fence error = %v, want ErrTenantWritesFenced",
			err,
		)
	}
	if err := store.WriteLogs(
		ctx,
		[]LogRecord{otlpFenceLog(tenantA, time.Now())},
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf(
			"tenant A log write after fence error = %v, want ErrTenantWritesFenced",
			err,
		)
	}
	if err := store.WriteSpans(
		ctx,
		[]Span{otlpFenceSpan(tenantB, time.Now())},
	); err != nil {
		t.Fatalf("tenant B span write was blocked by tenant A fence: %v", err)
	}
	if err := store.WriteLogs(
		ctx,
		[]LogRecord{otlpFenceLog(tenantB, time.Now())},
	); err != nil {
		t.Fatalf("tenant B log write was blocked by tenant A fence: %v", err)
	}

	beforeSpans, beforeLogs := memory.Len(tenantB)
	if err := store.WriteSpans(ctx, []Span{
		otlpFenceSpan(tenantB, time.Now().Add(time.Second)),
		otlpFenceSpan(tenantA, time.Now().Add(2*time.Second)),
	}); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf("mixed span batch error = %v, want ErrTenantWritesFenced", err)
	}
	if err := store.WriteLogs(ctx, []LogRecord{
		otlpFenceLog(tenantB, time.Now().Add(time.Second)),
		otlpFenceLog(tenantA, time.Now().Add(2*time.Second)),
	}); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf("mixed log batch error = %v, want ErrTenantWritesFenced", err)
	}
	afterSpans, afterLogs := memory.Len(tenantB)
	if afterSpans != beforeSpans || afterLogs != beforeLogs {
		t.Fatalf(
			"mixed fenced writes partially entered backend: got spans=%d logs=%d, want spans=%d logs=%d",
			afterSpans,
			afterLogs,
			beforeSpans,
			beforeLogs,
		)
	}
}

type blockingOTLPStore struct {
	Store
	tenantID string
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (s *blockingOTLPStore) WriteSpans(ctx context.Context, spans []Span) error {
	for i := range spans {
		if spans[i].TenantID != s.tenantID {
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
	return s.Store.WriteSpans(ctx, spans)
}

func commitOTLPEraseFence(
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
				return errors.New("tenant was not eligible for OTLP fence")
			}
			return nil
		},
	)
}

func insertOTLPFenceTenant(
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

func otlpFenceSpan(tenantID string, ts time.Time) Span {
	return Span{
		TenantID: tenantID,
		TraceID:  fmt.Sprintf("trace-%d", ts.UnixNano()),
		SpanID:   fmt.Sprintf("span-%d", ts.UnixNano()),
		Name:     "fence-test",
		Service:  "fence-test",
		Start:    ts,
	}
}

func otlpFenceLog(tenantID string, ts time.Time) LogRecord {
	return LogRecord{
		TenantID: tenantID,
		TS:       ts,
		Service:  "fence-test",
		Body:     fmt.Sprintf("fence-test-%d", ts.UnixNano()),
	}
}
