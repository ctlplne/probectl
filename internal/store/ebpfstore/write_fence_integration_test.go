// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package ebpfstore

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

// TestEBPFEraseWriteFenceTwoTenant proves DATA-ac4ea7a3 at the eBPF storage
// boundary. An Insert already holding the shared writer lease must drain before
// the exclusive lifecycle fence commits. Later aggregates for that tenant fail
// before the backend while a different tenant remains writable.
func TestEBPFEraseWriteFenceTwoTenant(t *testing.T) {
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
	tenantA := insertEBPFFenceTenant(t, ctx, pool, fmt.Sprintf("ebpf-fence-a-%d", stamp))
	tenantB := insertEBPFFenceTenant(t, ctx, pool, fmt.Sprintf("ebpf-fence-b-%d", stamp))
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
	})
	memory := NewMemory()
	blocking := &blockingEBPFInsert{
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
			[]Edge{ebpfFenceEdge(tenantA, time.Now())},
		)
	}()
	select {
	case <-blocking.entered:
	case <-ctx.Done():
		t.Fatal("in-flight eBPF Insert did not enter the backend")
	}

	fenceDone := make(chan error, 1)
	go func() {
		fenceDone <- commitEBPFEraseFence(ctx, pool, tenantA)
	}()
	select {
	case err := <-fenceDone:
		t.Fatalf("erasure fence did not drain the in-flight eBPF write: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(blocking.release)
	if err := <-insertDone; err != nil {
		t.Fatalf("in-flight eBPF Insert: %v", err)
	}
	if err := <-fenceDone; err != nil {
		t.Fatalf("commit erasure fence: %v", err)
	}

	if err := store.Insert(
		ctx,
		[]Edge{ebpfFenceEdge(tenantA, time.Now().Add(time.Second))},
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf(
			"tenant A eBPF Insert after fence error = %v, want ErrTenantWritesFenced",
			err,
		)
	}
	if err := store.Insert(
		ctx,
		[]Edge{ebpfFenceEdge(tenantB, time.Now())},
	); err != nil {
		t.Fatalf("tenant B eBPF Insert was blocked by tenant A fence: %v", err)
	}

	beforeMixed, err := memory.TopEdges(ctx, tenantB, EdgeQuery{})
	if err != nil {
		t.Fatalf("read tenant B before mixed batch: %v", err)
	}
	if err := store.Insert(
		ctx,
		[]Edge{
			ebpfFenceEdge(tenantB, time.Now().Add(time.Second)),
			ebpfFenceEdge(tenantA, time.Now().Add(2*time.Second)),
		},
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf(
			"mixed fenced eBPF batch error = %v, want ErrTenantWritesFenced",
			err,
		)
	}
	afterMixed, err := memory.TopEdges(ctx, tenantB, EdgeQuery{})
	if err != nil {
		t.Fatalf("read tenant B after mixed batch: %v", err)
	}
	if len(afterMixed) != len(beforeMixed) {
		t.Fatalf(
			"mixed fenced eBPF batch partially entered backend: edges=%d, want %d",
			len(afterMixed),
			len(beforeMixed),
		)
	}
}

type blockingEBPFInsert struct {
	Store
	tenantID string
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (s *blockingEBPFInsert) Insert(
	ctx context.Context,
	edges []Edge,
) error {
	for i := range edges {
		if edges[i].TenantID != s.tenantID {
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
	return s.Store.Insert(ctx, edges)
}

func commitEBPFEraseFence(
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
				return errors.New("tenant was not eligible for eBPF fence")
			}
			return nil
		},
	)
}

func ebpfFenceEdge(tenantID string, windowStart time.Time) Edge {
	return Edge{
		TenantID:    tenantID,
		AgentID:     "ebpf-agent",
		WindowStart: windowStart,
		SrcWorkload: "source",
		DstWorkload: "destination",
		Bytes:       1,
	}
}

func insertEBPFFenceTenant(
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
