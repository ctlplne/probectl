// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

//go:build integration || isolation

package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

func TestCanonicalPrefixNetworkIsExplicitTenantScopedAndTransactional(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	var tenants []string
	for _, suffix := range []string{"a", "b"} {
		row, err := NewTenants(pool).Create(ctx, fmt.Sprintf("prefix-network-%s-%d", suffix, time.Now().UnixNano()), suffix)
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, row.ID)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Errorf("clean prefix tenants: %v", err)
		}
	})
	contextID, prefixID, deviceID, foreignID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	rangeTag, manualTag := uuid.NewString(), uuid.NewString()
	repo := NewEntityRegistry(pool)
	run := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range tenants {
		run(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label) VALUES ($1,$2,$3,$4,'same-site','same-vrf')`, tenant, contextID, uuid.NewString(), uuid.NewString()); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label) VALUES ($1,$2,$3,'prefix','10.2.0.0/24'),($1,$2,$4,'device','edge')`, tenant, contextID, prefixID, deviceID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'range'),($1,$3,'manual')`, tenant, rangeTag, manualTag); err != nil {
				return err
			}
			scope := tags.Scope{TenantID: tenant, ContextID: contextID}
			for _, rule := range []tags.Rule{
				{Scope: scope, TagID: rangeTag, TargetKind: "prefix", Match: "cidr", AddressSide: "prefix", CIDR: "10.2.0.0/24", Value: tenant},
				{Scope: scope, TagID: rangeTag, TargetKind: "prefix", Match: "cidr", AddressSide: "prefix", CIDR: "2001:db8:2::/48", Value: "v6-" + tenant},
			} {
				if _, err := (TagRules{}).Create(ctx, sc, rule); err != nil {
					return err
				}
			}
			_, err := (TagAssignments{}).CreateManual(ctx, sc, ManualTagAssignmentInput{Scope: scope, TagID: manualTag, TargetKind: "prefix", TargetID: prefixID, Value: "retained"})
			return err
		})
	}
	resolve := func(tenant string) map[string]string {
		t.Helper()
		out, err := NewTagSnapshots(pool).ResolveSubject(tenancy.WithTenant(ctx, tenancy.ID(tenant)), tags.Scope{TenantID: tenant, ContextID: contextID}, TagSubjectReference{Kind: "prefix", ID: prefixID}, 8<<20)
		if err != nil {
			t.Fatal(err)
		}
		values := map[string]string{}
		for _, item := range out.Items {
			values[item.Key] = item.Value
		}
		if values["manual"] != "retained" {
			t.Fatal("network metadata changed canonical assignments")
		}
		return values
	}
	a, b := tenants[0], tenants[1]
	if resolve(a)["range"] != "" {
		t.Fatal("a display label became an address fact")
	}
	var first entity.Record
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		var err error
		first, err = repo.SetEntityNetworkPrefix(ctx, sc, contextID, prefixID, "10.2.0.129/25")
		return err
	})
	if first.ID != prefixID || first.NetworkPrefix != "10.2.0.128/25" || resolve(a)["range"] != a || resolve(b)["range"] != "" {
		t.Fatal("typed prefix range lost canonical identity or tenant isolation")
	}
	run(a, func(ctx context.Context, sc tenancy.Scope) error {
		row, err := repo.SetEntityNetworkPrefix(ctx, sc, contextID, prefixID, "10.2.0.128/25")
		if err == nil && !row.UpdatedAt.Equal(first.UpdatedAt) {
			t.Fatal("identical network rewrote metadata time")
		}
		return err
	})
	rollback := errors.New("planted audit failure")
	if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		if _, err := repo.SetEntityNetworkPrefix(ctx, sc, contextID, prefixID, "10.9.0.0/16"); err != nil {
			return err
		}
		return rollback
	}); !errors.Is(err, rollback) {
		t.Fatal("metadata transaction ignored failed audit")
	}
	got, err := repo.GetEntity(tenancy.WithTenant(ctx, tenancy.ID(a)), entity.Scope{TenantID: a, ContextID: contextID}, prefixID)
	if err != nil || got.NetworkPrefix != first.NetworkPrefix {
		t.Fatal("failed audit committed a network change")
	}
	for _, tc := range []struct{ network, want string }{{"10.2.0.0/23", ""}, {"2001:db8:2::/48", "v6-" + a}, {"2001:db8:2::/47", ""}, {"", ""}} {
		run(a, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := repo.SetEntityNetworkPrefix(ctx, sc, contextID, prefixID, tc.network)
			return err
		})
		if resolve(a)["range"] != tc.want {
			t.Fatal("whole-prefix containment or explicit clear failed")
		}
	}
	run(b, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,network_prefix) VALUES ($1,$2,$3,'prefix','foreign','10.2.0.0/24')`, b, contextID, foreignID)
		return err
	})
	for _, id := range []string{foreignID, deviceID} {
		run(a, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := repo.SetEntityNetworkPrefix(ctx, sc, contextID, id, "10.2.0.0/24"); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatal("foreign or wrong-kind subject accepted network metadata")
			}
			return nil
		})
	}
	err = tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(a)), pool, func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `UPDATE entities SET network_prefix='10.2.0.0/24'::cidr WHERE tenant_id=$1 AND id=$2`, a, deviceID)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
		t.Fatal("network kind boundary was not enforced in storage")
	}
}
