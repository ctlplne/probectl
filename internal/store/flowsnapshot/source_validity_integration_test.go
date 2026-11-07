// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration

package flowsnapshot_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/ctlplne/probectl/internal/objectstore"
	"github.com/ctlplne/probectl/internal/store/flowsnapshot"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type sourceValidityObjectReads struct {
	objectstore.Store
	reads atomic.Int64
}

func (objects *sourceValidityObjectReads) Get(ctx context.Context, key string) (objectstore.Object, error) {
	objects.reads.Add(1)
	return objects.Store.Get(ctx, key)
}

func TestSnapshotsPostgresWholeSourceValidityKeepsChargeTenantAndCurrentRead(t *testing.T) {
	f := newPostgresFixture(t)
	if f == nil {
		return
	}
	const count = 50_000
	expected := map[string]json.RawMessage{}
	objects := &sourceValidityObjectReads{Store: f.objects}
	f.objects = objects
	f.validate = func(_ context.Context, scope flowsnapshot.Scope, body json.RawMessage) error {
		if !bytes.Equal(body, expected[scope.TenantID]) {
			return flowsnapshot.ErrNotFound
		}
		return nil
	}
	firstReplica := f.replica(tenancy.PooledRouter{}, t.TempDir())
	secondReplica := f.replica(tenancy.PooledRouter{}, t.TempDir())
	pages := map[string]flowsnapshot.Page{}
	for _, tenant := range []string{f.red.ID, f.blue.ID} {
		selectors := make([]string, count)
		for i := range selectors {
			selectors[i] = fmt.Sprintf("%s/original-flow-%d/1700000000987654321", tenant, i)
		}
		body, err := json.Marshal(struct{ Captures []string }{selectors})
		if err != nil || len(body) <= 8192 {
			t.Fatal("actual source validity fixture lacks its full intended population", err)
		}
		expected[tenant] = body
		input := postgresInput(2)
		input.Validity = body
		scope := flowsnapshot.Scope{TenantID: tenant, Owner: "routing-source-owner"}
		page, err := firstReplica.Create(t.Context(), scope, []string{"ai.query", "flow.read"}, 1, allowPostgresSnapshot, func(context.Context) (flowsnapshot.Input, error) { return input, nil })
		if err != nil {
			t.Fatal("actual source validity still refuses the complete admitted receipt", len(body), err)
		}
		pages[tenant] = page
		err = tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(tenant)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
			var role, sealed string
			var charged, size int64
			err := sc.Q.QueryRow(ctx, `SELECT current_user,private_header,charged_bytes,octet_length(private_header)::bigint FROM flow_snapshots WHERE tenant_id=$1 AND id=$2`, tenant, page.SnapshotID).Scan(&role, &sealed, &charged, &size)
			if err == nil && (role != tenancy.AppRole || size <= int64(len(body)) || charged < size || bytes.Contains([]byte(sealed), []byte(selectors[count-1]))) {
				t.Fatal("source validity lost app-role storage, complete byte charge or encryption", role, charged, size)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		if next, err := secondReplica.Resume(t.Context(), scope, page.NextCursor, allowPostgresSnapshot); err != nil || len(next.Rows) != 1 || !bytes.Equal(next.Rows[0], input.Rows[1]) {
			t.Fatal("actual replica lost its complete original source-policy receipt", err)
		}
	}
	foreign := flowsnapshot.Scope{TenantID: f.blue.ID, Owner: "routing-source-owner"}
	before := objects.reads.Load()
	if _, err := secondReplica.Resume(t.Context(), foreign, pages[f.red.ID].NextCursor, allowPostgresSnapshot); err == nil || objects.reads.Load() != before {
		t.Fatal("foreign source receipt reached another tenant's objects", err)
	}
	err := tenancy.InTenantReadSnapshot(tenancy.WithTenant(t.Context(), tenancy.ID(f.blue.ID)), f.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var rows int
		if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM flow_snapshots WHERE id=$1`, pages[f.red.ID].SnapshotID).Scan(&rows); err != nil {
			return err
		}
		if rows != 0 {
			t.Fatal("storage-layer row policy exposed foreign complete source receipt")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	delete(expected, f.red.ID)
	before = objects.reads.Load()
	if _, err := secondReplica.Resume(t.Context(), flowsnapshot.Scope{TenantID: f.red.ID, Owner: "routing-source-owner"}, pages[f.red.ID].NextCursor, allowPostgresSnapshot); !errors.Is(err, flowsnapshot.ErrNotFound) || objects.reads.Load() != before {
		t.Fatal("retired source receipt reached retained objects", err)
	}
	if _, err := secondReplica.Resume(t.Context(), foreign, pages[f.blue.ID].NextCursor, allowPostgresSnapshot); err != nil {
		t.Fatal("source receipt retirement changed its sibling tenant", err)
	}
	t.Log("real-integration: app-role Postgres/FORCE-RLS/envelope/complete50000-selector receipt per tenant/byte charge/replicas/current refusal/sibling; source policy modeled, no actor/RIB grant proof")
}
