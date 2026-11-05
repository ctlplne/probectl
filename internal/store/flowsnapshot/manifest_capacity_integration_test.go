// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowsnapshot_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/migrations"
)

func TestSnapshotsPostgresManifestChargeRepairAndBoundedRead(t *testing.T) {
	f := newPostgresFixture(t)
	if f == nil {
		return
	}
	ctx := t.Context()
	repair, err := migrations.FS.ReadFile("0173_flow_snapshot_manifest_capacity.sql")
	if err != nil {
		t.Fatal(err)
	}
	// A schema double covers existing physical-copy CHECK repair. Real tenant
	// isolation is exercised separately below through the application role.
	schema := "t_" + strings.ReplaceAll(f.red.ID, "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := f.admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.admin.Exec(context.Background(), "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	if _, err := f.admin.Exec(ctx, "CREATE TABLE "+quoted+".flow_snapshots(private_header text NOT NULL CONSTRAINT flow_snapshots_private_header_check CHECK(octet_length(private_header) BETWEEN 1 AND 65536), charged_bytes bigint NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.admin.Exec(ctx, `ALTER TABLE public.flow_snapshots ADD CONSTRAINT flow_snapshots_private_header_check CHECK(octet_length(private_header) BETWEEN 1 AND 65536) NOT VALID`); err != nil {
		t.Fatal(err)
	}
	id, err := crypto.UUIDv4()
	if err != nil {
		t.Fatal(err)
	}
	insert := func(tenant, marker string, charge int64) error {
		return tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO flow_snapshots(tenant_id,id,owner_id,generation,query_hash,object_lane,created_at,expires_at,row_count,page_size,permissions,private_header,charged_bytes,state)
			VALUES($1::uuid,$2::uuid,'manifest-owner',1,$3,'pooled',now(),now()+interval '1 hour',5000001,5000,ARRAY['flow.read','ai.query'],$4,$5,'ready')`, tenant, id, strings.Repeat("a", 64), strings.Repeat(marker, 100000), charge)
			return err
		})
	}
	var refusal *pgconn.PgError
	if err := insert(f.red.ID, "r", 104096); !errors.As(err, &refusal) || refusal.Code != "23514" {
		t.Fatal("restored original database manifest quota did not refuse", err)
	}
	for range 2 {
		if _, err := f.admin.Exec(ctx, string(repair)); err != nil {
			t.Fatal("manifest repair is not idempotent", err)
		}
	}
	if _, err := f.admin.Exec(ctx, "INSERT INTO "+quoted+".flow_snapshots(private_header,charged_bytes) VALUES(repeat('m',100000),104096)"); err != nil {
		t.Fatal("existing physical-copy manifest ceiling remains", err)
	}
	for _, expression := range []string{"('',4096)", "(repeat('m',100000),99999)"} {
		if _, err := f.admin.Exec(ctx, "INSERT INTO "+quoted+".flow_snapshots(private_header,charged_bytes) VALUES"+expression); err == nil {
			t.Fatal("physical-copy manifest lost nonempty or storage-charge enforcement")
		}
	}
	for index, tenant := range []string{f.red.ID, f.blue.ID} {
		marker := []string{"r", "b"}[index]
		if err := insert(tenant, marker, 104096); err != nil {
			t.Fatal("expanded charged manifest was refused", err)
		}
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var count int
			var own string
			if err := sc.Q.QueryRow(ctx, `SELECT count(*),min(private_header) FROM flow_snapshots WHERE id=$1::uuid`, id).Scan(&count, &own); err != nil {
				return err
			}
			if count != 1 || own != strings.Repeat(marker, 100000) {
				t.Fatal("equal-id charged metadata crossed storage tenant scope")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// These rows deliberately contain malformed encrypted metadata. A low
		// profile must return budget refusal from the SQL projection, before
		// decryption or any output callback. It must not become a crypto pass.
		low := flowsnapshot.New(f.pool, f.objects, tenancy.PooledRouter{}, tenancy.NewPostgresWriterFence(f.pool), f.validate,
			flowsnapshot.Config{ObjectBytes: 65536, TempDir: t.TempDir()})
		called := false
		err := low.Walk(ctx, flowsnapshot.Scope{TenantID: tenant, Owner: "manifest-owner"}, id, allowPostgresSnapshot,
			func(flowsnapshot.Header) error { called = true; return nil }, func([]json.RawMessage) error { called = true; return nil })
		if !errors.Is(err, flowsnapshot.ErrBudget) || called {
			t.Fatal("bounded SQL manifest read reached decryption/output or lost refusal", err)
		}
		denial := errors.New("current source permission refused")
		err = low.Walk(ctx, flowsnapshot.Scope{TenantID: tenant, Owner: "manifest-owner"}, id,
			func(context.Context, flowsnapshot.Scope, []string) error { return denial },
			func(flowsnapshot.Header) error { called = true; return nil }, func([]json.RawMessage) error { called = true; return nil })
		if !errors.Is(err, denial) || called {
			t.Fatal("SQL manifest size diagnostic preceded current source authorization", err)
		}
		err = low.Walk(ctx, flowsnapshot.Scope{TenantID: tenant, Owner: "other-owner"}, id, allowPostgresSnapshot,
			func(flowsnapshot.Header) error { called = true; return nil }, func([]json.RawMessage) error { called = true; return nil })
		if !errors.Is(err, flowsnapshot.ErrNotFound) || called {
			t.Fatal("manifest budget disclosed a foreign owner's metadata", err)
		}
	}
}
