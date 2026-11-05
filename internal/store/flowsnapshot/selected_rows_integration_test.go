// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowsnapshot_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/migrations"
)

func TestSnapshotsPostgresCompleteRowsPastFormerQuotaAndIdempotentRepair(t *testing.T) {
	f := newPostgresFixture(t)
	if f == nil {
		return
	}
	ctx := t.Context()
	// A count-only schema double tests repair of a pre-existing physical silo
	// constraint. Actual tenant/owner data-path proof below uses real pooled RLS.
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
	if _, err := f.admin.Exec(ctx, "CREATE TABLE "+quoted+".flow_snapshots(row_count integer CONSTRAINT flow_snapshots_row_count_check CHECK(row_count BETWEEN 0 AND 50000))"); err != nil {
		t.Fatal(err)
	}
	repair, err := migrations.FS.ReadFile("0171_flow_snapshot_row_capacity.sql")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := f.admin.Exec(context.Background(), string(repair)); err != nil {
			t.Error("restoring current snapshot constraint", err)
		}
	})
	replica := f.replica(tenancy.PooledRouter{}, t.TempDir())
	scope := flowsnapshot.Scope{TenantID: f.red.ID, Owner: "selected-owner"}
	if _, err := f.admin.Exec(ctx, "ALTER TABLE public.flow_snapshots DROP CONSTRAINT flow_snapshots_row_count_check; ALTER TABLE public.flow_snapshots ADD CONSTRAINT flow_snapshots_row_count_check CHECK(row_count BETWEEN 0 AND 50000)"); err != nil {
		t.Fatal(err)
	}
	_, err = replica.Create(ctx, scope, []string{"flow.read", "ai.query"}, 4999, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return postgresInput(50001), nil })
	var refusal *pgconn.PgError
	if !errors.As(err, &refusal) || refusal.Code != "23514" {
		t.Fatal("restored original database quota did not refuse intended larger workload", err)
	}
	for range 2 {
		if _, err := f.admin.Exec(ctx, string(repair)); err != nil {
			t.Fatal("snapshot capacity repair is not idempotent", err)
		}
	}
	if _, err := f.admin.Exec(ctx, "INSERT INTO "+quoted+".flow_snapshots(row_count) VALUES(50001)"); err != nil {
		t.Fatal("existing silo quota was not repaired", err)
	}
	if _, err := f.admin.Exec(ctx, "INSERT INTO "+quoted+".flow_snapshots(row_count) VALUES(-1)"); err == nil {
		t.Fatal("silo nonnegative representation guard disappeared")
	}
	otherReplica := f.replica(tenancy.PooledRouter{}, t.TempDir())
	for _, tenant := range []string{f.red.ID, f.blue.ID} {
		owned := flowsnapshot.Scope{TenantID: tenant, Owner: scope.Owner}
		input := postgresInput(50001)
		input.Query = []byte(`{"table_rows":50001}`)
		page, err := replica.Create(ctx, owned, []string{"flow.read", "ai.query"}, 4999, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return input, nil })
		if err != nil {
			t.Fatal("complete Postgres snapshot retains former row quota", err)
		}
		first := page
		count := 0
		for {
			if page.SelectedRows != 50001 || page.Offset != count {
				t.Fatal("snapshot count or offset changed")
			}
			for _, row := range page.Rows {
				if !strings.Contains(string(row), fmt.Sprintf(`"fixture_row":"%05d"`, count)) || !strings.Contains(string(row), `"18446744073709551616001"`) {
					t.Fatal("real snapshot changed original row", count)
				}
				count++
			}
			if page.NextCursor == "" {
				break
			}
			page, err = otherReplica.Resume(ctx, owned, page.NextCursor, allowPostgresSnapshot)
			if err != nil {
				t.Fatal(err)
			}
		}
		if count != 50001 {
			t.Fatal("real snapshot truncated", count)
		}
		foreign := flowsnapshot.Scope{TenantID: f.blue.ID, Owner: owned.Owner}
		if tenant == f.blue.ID {
			foreign.TenantID = f.red.ID
		}
		if _, err := otherReplica.Resume(ctx, foreign, first.NextCursor, allowPostgresSnapshot); !errors.Is(err, flowsnapshot.ErrNotFound) {
			t.Fatal("real snapshot crossed tenant", err)
		}
	}
}
