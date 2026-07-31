// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package endpointstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// TestEndpointEraseWriteFenceTwoTenant proves DATA-872cb7eb at the endpoint
// storage boundary. An Insert already holding the shared writer lease must
// drain before the exclusive lifecycle fence commits. Later events for that
// tenant fail before the backend while a different tenant remains writable.
func TestEndpointEraseWriteFenceTwoTenant(t *testing.T) {
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
	tenantA := insertEndpointFenceTenant(t, ctx, pool, fmt.Sprintf("endpoint-fence-a-%d", stamp))
	tenantB := insertEndpointFenceTenant(t, ctx, pool, fmt.Sprintf("endpoint-fence-b-%d", stamp))
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
	})
	memory := NewMemory()
	blocking := &blockingEndpointInsert{
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
			[]Event{endpointFenceEvent(tenantA, "in-flight")},
		)
	}()
	select {
	case <-blocking.entered:
	case <-ctx.Done():
		t.Fatal("in-flight endpoint Insert did not enter the backend")
	}

	fenceDone := make(chan error, 1)
	go func() {
		fenceDone <- commitEndpointEraseFence(ctx, pool, tenantA)
	}()
	select {
	case err := <-fenceDone:
		t.Fatalf(
			"erasure fence did not drain the in-flight endpoint write: %v",
			err,
		)
	case <-time.After(100 * time.Millisecond):
	}

	close(blocking.release)
	if err := <-insertDone; err != nil {
		t.Fatalf("in-flight endpoint Insert: %v", err)
	}
	if err := <-fenceDone; err != nil {
		t.Fatalf("commit erasure fence: %v", err)
	}

	if err := store.Insert(
		ctx,
		[]Event{endpointFenceEvent(tenantA, "after-fence")},
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf(
			"tenant A endpoint Insert after fence error = %v, want ErrTenantWritesFenced",
			err,
		)
	}
	if err := store.Insert(
		ctx,
		[]Event{endpointFenceEvent(tenantB, "tenant-b")},
	); err != nil {
		t.Fatalf("tenant B endpoint Insert was blocked by tenant A fence: %v", err)
	}

	beforeMixed, err := memory.Latest(ctx, tenantB)
	if err != nil {
		t.Fatalf("read tenant B before mixed batch: %v", err)
	}
	if err := store.Insert(
		ctx,
		[]Event{
			endpointFenceEvent(tenantB, "mixed-b"),
			endpointFenceEvent(tenantA, "mixed-a"),
		},
	); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf(
			"mixed fenced endpoint batch error = %v, want ErrTenantWritesFenced",
			err,
		)
	}
	afterMixed, err := memory.Latest(ctx, tenantB)
	if err != nil {
		t.Fatalf("read tenant B after mixed batch: %v", err)
	}
	if len(afterMixed) != len(beforeMixed) {
		t.Fatalf(
			"mixed fenced endpoint batch partially entered backend: events=%d, want %d",
			len(afterMixed),
			len(beforeMixed),
		)
	}
}

type blockingEndpointInsert struct {
	Store
	tenantID string
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
}

func (s *blockingEndpointInsert) Insert(
	ctx context.Context,
	events []Event,
) error {
	for i := range events {
		if events[i].TenantID != s.tenantID {
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
	return s.Store.Insert(ctx, events)
}

func commitEndpointEraseFence(
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
				return errors.New("tenant was not eligible for endpoint fence")
			}
			return nil
		},
	)
}

func endpointFenceEvent(tenantID, signalKey string) Event {
	return Event{
		TenantID:   tenantID,
		AgentID:    "endpoint-agent",
		Type:       "network",
		SignalKey:  signalKey,
		ObservedAt: time.Now(),
	}
}

func insertEndpointFenceTenant(
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
