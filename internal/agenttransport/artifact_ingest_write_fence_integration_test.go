// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package agenttransport

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
	"google.golang.org/protobuf/proto"

	"github.com/ctlplne/probectl/internal/bus"
	"github.com/ctlplne/probectl/internal/crypto"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
	resultv1 "github.com/ctlplne/probectl/internal/gen/probectl/result/v1"
	"github.com/ctlplne/probectl/internal/store/migrate"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
	"github.com/ctlplne/probectl/migrations"
)

func TestObjectArtifactEraseWriteFenceTwoTenant(t *testing.T) {
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
	tenantA := insertArtifactFenceTenant(ctx, t, pool, fmt.Sprintf("artifact-fence-a-%d", stamp))
	tenantB := insertArtifactFenceTenant(ctx, t, pool, fmt.Sprintf("artifact-fence-b-%d", stamp))
	t.Cleanup(func() {
		_, _ = pool.Exec(
			context.Background(),
			`DELETE FROM public.tenants WHERE id IN ($1::uuid, $2::uuid)`,
			tenantA,
			tenantB,
		)
	})

	published := &artifactCaptureBus{}
	svc := &service{
		pool:  pool,
		bus:   published,
		log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		fence: tenancy.NewPostgresWriterFence(pool),
	}
	if err := svc.ingest(ctx, artifactAgentID(tenantA, "agent-a"), artifactResultRequest(t, tenantA, "before")); err != nil {
		t.Fatalf("active tenant A artifact ingest: %v", err)
	}
	if err := commitArtifactEraseFence(ctx, pool, tenantA); err != nil {
		t.Fatalf("commit tenant-A erasure fence: %v", err)
	}
	if err := svc.ingest(ctx, artifactAgentID(tenantA, "agent-a"), artifactResultRequest(t, tenantA, "after")); !errors.Is(err, tenancy.ErrTenantWritesFenced) {
		t.Fatalf("tenant A artifact ingest after fence error = %v, want ErrTenantWritesFenced", err)
	}
	if err := svc.ingest(ctx, artifactAgentID(tenantB, "agent-b"), artifactResultRequest(t, tenantB, "allowed")); err != nil {
		t.Fatalf("tenant B artifact ingest was blocked by tenant A fence: %v", err)
	}

	if got := published.Count(); got != 2 {
		t.Fatalf("published artifact-bearing results = %d, want active A plus active B only", got)
	}
}

func artifactAgentID(tenantID, agentID string) crypto.SPIFFEID {
	return crypto.SPIFFEID{
		TrustDomain: crypto.TrustDomain,
		TenantID:    tenantID,
		AgentID:     agentID,
		Plane:       "agent",
	}
}

func artifactResultRequest(t *testing.T, tenantID, suffix string) *agentv1.StreamResultsRequest {
	t.Helper()
	payload, err := proto.Marshal(&resultv1.Result{
		CanaryType:        "browser",
		ServerAddress:     "https://browser.example",
		StartTimeUnixNano: time.Now().UnixNano(),
		DurationNano:      int64(time.Millisecond),
		Success:           false,
		Attributes: map[string]string{
			"browser.screenshot.key": "tenant/" + tenantID + "/browser/" + suffix + ".png",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.StreamResultsRequest{Payload: payload}
}

type artifactCaptureBus struct {
	mu    sync.Mutex
	count int
}

func (b *artifactCaptureBus) Publish(context.Context, string, []byte, []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.count++
	return nil
}

func (b *artifactCaptureBus) Subscribe(context.Context, string, string, bus.Handler) error {
	return nil
}

func (b *artifactCaptureBus) Close() error { return nil }

func (b *artifactCaptureBus) Count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.count
}

func commitArtifactEraseFence(ctx context.Context, pool *pgxpool.Pool, tenantID string) error {
	return tenancy.InProvider(ctx, pool, func(ctx context.Context, q tenancy.Querier) error {
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
			return errors.New("tenant was not eligible for object-artifact fence")
		}
		return nil
	})
}

func insertArtifactFenceTenant(ctx context.Context, t *testing.T, pool *pgxpool.Pool, slug string) string {
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
