// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//go:build integration

package tenantlife

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/imfeelingtheagi/probectl/internal/audit"
	"github.com/imfeelingtheagi/probectl/internal/store/flowstore"
	"github.com/imfeelingtheagi/probectl/internal/store/migrate"
	"github.com/imfeelingtheagi/probectl/internal/store/tsdb"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
	"github.com/imfeelingtheagi/probectl/internal/testsupport"
	"github.com/imfeelingtheagi/probectl/migrations"
)

// The S-T5 named integration suite (live Postgres): a tenant's data is
// EXPORTED (round-trip with row-accurate counts), then VERIFIABLY DELETED —
// gone from every Postgres tenant-owned table and the provider rows about it
// — while a second tenant's rows are untouched, the deletion is attested on
// the provider audit chain, and the retention policy round-trips. Pooled
// scoping is RLS; the siloed routing leg is covered by the S-T2 suite (the
// engine deletes through the same InTenant path).
func itPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := testsupport.PostgresDSN()
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if err := pool.Ping(context.Background()); err != nil {
		testsupport.SkipOrFatal(t, "postgres unavailable: %v", err)
	}
	if _, err := migrate.New(migrations.FS, nil).Apply(context.Background(), pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool
}

func mkTenant(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (slug, name) VALUES ($1, $1)
		 ON CONFLICT (slug) DO UPDATE SET name = EXCLUDED.name RETURNING id::text`, slug).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func seedTenant(t *testing.T, pool *pgxpool.Pool, tenantID, name string) {
	t.Helper()
	tctx := tenancy.WithTenant(context.Background(), tenancy.ID(tenantID))
	err := tenancy.InTenant(tctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := sc.Q.Exec(ctx,
			`INSERT INTO tests (tenant_id, name, type, target, interval_seconds, timeout_seconds, params, enabled)
			 VALUES ($1, $2, 'icmp', '192.0.2.1', 60, 5, '{}'::jsonb, true)`, tenantID, name); err != nil {
			return err
		}
		_, err := sc.Q.Exec(ctx,
			`INSERT INTO audit_events (tenant_id, seq, actor, action, target, data, prev_hash, hash)
			 VALUES ($1, 1, 'it', 'seed', 'x', '{}'::jsonb, '', 'h')
			 ON CONFLICT DO NOTHING`, tenantID)
		return err
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
}

func countTests(t *testing.T, pool *pgxpool.Pool, tenantID string) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM tests WHERE tenant_id = $1`, tenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLifecycleEndToEndPG(t *testing.T) {
	pool := itPool(t)
	// The lifecycle export enumerates the live public tenant-table catalog.
	// Serialize it with integration tests that temporarily mutate that catalog.
	// Register the pool first so the lock cleanup runs before pool shutdown.
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)

	var victim, bystander string
	if ok := t.Run("round_trip", func(t *testing.T) {
		victim, bystander = runLifecycleEndToEndPG(t, pool)
	}); !ok {
		return
	}
	// The child cleanup has run before t.Run returns. Pin that both the erased
	// victim tombstone and the bystander fixture are gone, so repeated gates do
	// not make the shared integration database grow forever.
	for _, tenantID := range []string{victim, bystander} {
		var remaining int
		if err := pool.QueryRow(context.Background(),
			`SELECT count(*) FROM tenants WHERE id = $1`, tenantID).Scan(&remaining); err != nil {
			t.Fatalf("verify lifecycle fixture cleanup: %v", err)
		}
		if remaining != 0 {
			t.Fatalf("lifecycle fixture tenant %s remains after cleanup", tenantID)
		}
	}
}

func runLifecycleEndToEndPG(t *testing.T, pool *pgxpool.Pool) (string, string) {
	t.Helper()
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	stamp := fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	victim := mkTenant(t, pool, "it-life-a-"+stamp)
	bystander := mkTenant(t, pool, "it-life-b-"+stamp)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(),
			`DELETE FROM tenants WHERE id = $1 OR id = $2`, victim, bystander); err != nil {
			t.Errorf("cleanup lifecycle integration tenants: %v", err)
		}
	})
	seedTenant(t, pool, victim, "victim-probe")
	seedTenant(t, pool, bystander, "bystander-probe")

	flows := flowstore.NewMemory()
	_ = flows.Insert(ctx, []flowstore.Row{
		{TenantID: victim, TS: time.Now(), Bytes: 1},
		{TenantID: bystander, TS: time.Now(), Bytes: 2},
	})
	mem := tsdb.NewMemory()
	sink := func(ctx context.Context, actor, action, target string, data map[string]any) error {
		_, err := audit.ProviderAppend(ctx, pool, actor, action, target, data)
		return err
	}
	e := New(pool, flows, nil, mem, sink, "backups expire after 14 days (it)", log)

	// EXPORT round-trip: the bundle carries the victim's tests row, counts
	// match, and nothing of the bystander.
	var buf bytes.Buffer
	man, err := e.Export(ctx, victim, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if man.Tables["tests"] != 1 || man.Flows != 1 {
		t.Fatalf("manifest: %+v", man)
	}
	gz, _ := gzip.NewReader(&buf)
	tr := tar.NewReader(gz)
	var testsJSONL string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "postgres/tests.jsonl" {
			b, _ := io.ReadAll(tr)
			testsJSONL = string(b)
		}
	}
	if !strings.Contains(testsJSONL, "victim-probe") || strings.Contains(testsJSONL, "bystander-probe") {
		t.Fatalf("export scoping: %s", testsJSONL)
	}

	// Retention round-trip.
	days := 14
	if err := e.SetRetention(ctx, RetentionPolicy{TenantID: victim, FlowRetentionDays: &days, UpdatedBy: "it"}); err != nil {
		t.Fatal(err)
	}
	p, err := e.RetentionFor(ctx, victim)
	if err != nil || p.FlowRetentionDays == nil || *p.FlowRetentionDays != 14 {
		t.Fatalf("retention round-trip: %+v %v", p, err)
	}

	// ERASE: gone from every store; the bystander untouched; attested.
	providerHead, err := audit.ProviderHeadSeq(ctx, pool)
	if err != nil {
		t.Fatalf("provider head: %v", err)
	}
	att, err := e.Erase(ctx, victim, "it-life-a-"+stamp, "it-admin")
	if err != nil {
		t.Fatal(err)
	}
	if !att.Complete {
		t.Fatalf("attestation incomplete: %+v", att.Stores)
	}
	if n := countTests(t, pool, victim); n != 0 {
		t.Fatalf("victim tests remaining: %d", n)
	}
	if n := countTests(t, pool, bystander); n != 1 {
		t.Fatalf("bystander tests must be untouched: %d", n)
	}
	var status string
	_ = pool.QueryRow(ctx, `SELECT status FROM tenants WHERE id = $1`, victim).Scan(&status)
	if status != "deleted" {
		t.Fatalf("tombstone status: %q", status)
	}
	// The retention row about the victim is gone too (provider rows).
	var n int64
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM tenant_retention WHERE tenant_id = $1`, victim).Scan(&n)
	if n != 0 {
		t.Fatalf("tenant_retention remaining: %d", n)
	}
	// The attestation rode the provider audit chain and ITS suffix verifies.
	// (Anchored on the pre-erase head: the provider stream is global and the
	// CI database is shared with packages that test tamper DETECTION — this
	// test asserts the integrity of what IT appended, not world history.)
	if err := audit.ProviderVerifyFrom(ctx, pool, providerHead); err != nil {
		t.Fatalf("provider chain must verify after the attestation: %v", err)
	}
	return victim, bystander
}
