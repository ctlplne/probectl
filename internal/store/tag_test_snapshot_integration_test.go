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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ctlplne/probectl/internal/tags"
	"github.com/ctlplne/probectl/internal/tenancy"
	"github.com/ctlplne/probectl/internal/testsupport"
)

// This proves the request-local PostgreSQL reader, not public transport,
// model, metric-source or release/sender receipt behavior.
func TestTestTagSnapshotKeepsCurrentOwnedIdentityAndTenantScope(t *testing.T) {
	ctx := t.Context()
	pool := setup(ctx, t)
	t.Cleanup(pool.Close)
	testsupport.LockPostgresPublicCatalog(t, pool)
	var tenants []string
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error("owned test tag fixture cleanup failed")
		}
	})
	for _, lane := range []string{"a", "b"} {
		tenant, err := NewTenants(pool).Create(ctx, fmt.Sprintf("test-tag-snapshot-%s-%d", lane, time.Now().UnixNano()), "Test tags "+lane)
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
	}
	contextID, movedContext, customerID, siteID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	testIDs, unboundIDs := map[string]string{}, map[string]string{}
	rules := map[string]tags.Rule{}
	snapshots := NewTagSnapshots(pool)
	registry := NewEntityRegistry(pool)
	wideValue := strings.Repeat("🌐", tags.MaxValueCharacters)
	mutate := func(tenant string, fn func(context.Context, tenancy.Scope) error) {
		t.Helper()
		if err := tenancy.InTenant(tenancy.WithTenant(ctx, tenancy.ID(tenant)), pool, fn); err != nil {
			t.Fatal(err)
		}
	}
	for _, tenant := range tenants {
		// The pre-existing tests table has globally unique IDs. Context and tag
		// IDs and both configured addresses deliberately coincide across lanes.
		testIDs[tenant], unboundIDs[tenant] = uuid.NewString(), uuid.NewString()
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			for _, id := range []string{contextID, movedContext} {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
					VALUES ($1,$2,$3,$4,$5,'owned-vrf')`, tenant, id, uuid.NewString(), uuid.NewString(), "owned-"+tenant); err != nil {
					return err
				}
			}
			for _, id := range []string{testIDs[tenant], unboundIDs[tenant]} {
				if _, err := sc.Q.Exec(ctx, `INSERT INTO tests(tenant_id,id,name,target) VALUES ($1,$2,'same-test','https://192.0.2.10/health')`, tenant, id); err != nil {
					return err
				}
			}
			if err := registry.AssignPathTestContext(ctx, sc, testIDs[tenant], contextID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO tenant_tag_definitions(tenant_id,id,key) VALUES ($1,$2,'customer'),($1,$3,'site')`, tenant, customerID, siteID); err != nil {
				return err
			}
			rule, err := (TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: customerID, TargetKind: "test", Match: "name_pattern", NamePattern: "^same-test$", Value: "rule-" + tenant})
			if err != nil {
				return err
			}
			rules[tenant] = rule
			_, err = (TagRules{}).Create(ctx, sc, tags.Rule{Scope: tags.Scope{TenantID: tenant, ContextID: contextID}, TagID: siteID, TargetKind: "test", Match: "cidr", AddressSide: "test", CIDR: "192.0.2.0/24", Value: wideValue})
			return err
		})
	}
	for lane, tenant := range tenants {
		owned := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		foreign := tenants[1-lane]
		ids := []string{testIDs[tenant], testIDs[foreign], testIDs[tenant], unboundIDs[tenant], uuid.NewString(), "not-an-id"}
		if partial, err := snapshots.LoadTests(ctx, ids, 4<<20); !errors.Is(err, tags.ErrScopeMismatch) || partial != nil {
			t.Fatal("missing tenant acquired a test snapshot")
		}
		snapshot, err := snapshots.LoadTests(owned, ids, 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		allowed := map[string]bool{contextID: true}
		read := func(snapshot *TestTagSnapshot, want string) *ResolvedTagSubject {
			t.Helper()
			item, err := snapshot.ResolveContext(owned, tenant, testIDs[tenant], allowed, 1<<20)
			if err != nil || item == nil || item.Scope.TenantID != tenant || item.Scope.ContextID != contextID || item.ID != testIDs[tenant] || item.Kind != "test" || item.Revision <= 0 || item.AsOf.IsZero() || len(item.Items) != 2 {
				t.Fatal("owned test tag snapshot lost identity, revision or current context")
			}
			values := map[string]string{}
			for _, value := range item.Items {
				wantID := customerID
				if value.Key == "site" {
					wantID = siteID
				}
				if value.TagID != wantID || value.Source != "rule" || value.Revision != item.Revision {
					t.Fatal("test metadata lost immutable tag identity or provenance")
				}
				values[value.Key] = value.Value
			}
			if values["customer"] != want || values["site"] != wideValue {
				t.Fatal("current owned test name/CIDR rules lost exact values")
			}
			return item
		}
		original := read(snapshot, "rule-"+tenant)
		original.Items[0].Value = "mutated-copy"
		read(snapshot, "rule-"+tenant)
		records, err := snapshot.Contexts()
		if err != nil || len(records) != 1 || records[0].TenantID != tenant || records[0].ContextID != contextID || records[0].SiteLabel != "owned-"+tenant {
			t.Fatal("test snapshot policy facts crossed tenant or context")
		}
		records[0].SiteLabel = "mutated-copy"
		again, err := snapshot.Contexts()
		if err != nil || again[0].SiteLabel != "owned-"+tenant {
			t.Fatal("test snapshot policy facts were mutable")
		}
		for _, id := range []string{testIDs[foreign], unboundIDs[tenant], "not-an-id"} {
			if item, err := snapshot.ResolveContext(owned, tenant, id, allowed, 1<<20); err != nil || item != nil {
				t.Fatal("foreign, unbound or malformed test acquired metadata")
			}
		}
		if item, err := snapshot.ResolveContext(owned, tenant, testIDs[tenant], map[string]bool{}, 1<<20); err != nil || item != nil {
			t.Fatal("denied test context disclosed metadata")
		}
		if item, err := snapshot.ResolveContext(owned, tenant, testIDs[tenant], nil, 1<<20); !errors.Is(err, tags.ErrScopeMismatch) || item != nil {
			t.Fatal("missing test context policy did not fail closed")
		}
		if item, err := snapshot.ResolveContext(tenancy.WithTenant(ctx, tenancy.ID(foreign)), foreign, testIDs[tenant], allowed, 1<<20); !errors.Is(err, tags.ErrScopeMismatch) || item != nil {
			t.Fatal("foreign tenant reused a test snapshot")
		}
		if item, err := snapshot.ResolveContext(owned, tenant, testIDs[tenant], allowed, 1); !errors.Is(err, ErrTagSnapshotBudget) || item != nil {
			t.Fatal("test projection returned partial values beyond its budget")
		}
		if item, err := snapshot.ResolveContext(owned, tenant, testIDs[tenant], allowed, 80<<10); !errors.Is(err, ErrTagSnapshotBudget) || item != nil {
			t.Fatal("wide test metadata escaped the complete projection budget")
		}
		if partial, err := snapshots.LoadTests(owned, ids, 1); !errors.Is(err, ErrTagSnapshotBudget) || partial != nil {
			t.Fatal("test snapshot returned partial values beyond its budget")
		}
		if partial, err := snapshots.LoadTests(owned, []string{testIDs[tenant]}, 80<<10); !errors.Is(err, ErrTagSnapshotBudget) || partial != nil {
			t.Fatal("wide test rule escaped the complete source budget")
		}
		hints, err := snapshots.LoadTests(owned, []string{"same-test", "192.0.2.10", "https://192.0.2.10/health"}, 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		if item, err := hints.ResolveContext(owned, tenant, testIDs[tenant], allowed, 1<<20); err != nil || item != nil {
			t.Fatal("test name or address supplied an implicit owned identity")
		}
		cancelled, cancel := context.WithCancel(owned)
		cancel()
		if item, err := snapshot.ResolveContext(cancelled, tenant, testIDs[tenant], allowed, 1<<20); !errors.Is(err, context.Canceled) || item != nil {
			t.Fatal("cancelled test projection returned partial metadata")
		}
		if partial, err := snapshots.LoadTests(cancelled, ids, 4<<20); !errors.Is(err, context.Canceled) || partial != nil {
			t.Fatal("cancelled test snapshot returned partial metadata")
		}
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			rule := rules[tenant]
			rule.Value = "changed-" + tenant
			_, err := (TagRules{}).Update(ctx, sc, rule)
			return err
		})
		fresh, err := snapshots.LoadTests(owned, ids, 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		changed := read(fresh, "changed-"+tenant)
		if changed.Revision <= original.Revision {
			t.Fatal("changed test rule did not advance the fresh snapshot")
		}
		read(snapshot, "rule-"+tenant)
	}
	// Both foreign rows remain present through both directions of the RLS
	// checks above; move/delete only after the paired reads are complete.
	for _, tenant := range tenants {
		owned := tenancy.WithTenant(ctx, tenancy.ID(tenant))
		ids := []string{testIDs[tenant]}
		allowed := map[string]bool{contextID: true}
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			return registry.AssignPathTestContext(ctx, sc, testIDs[tenant], movedContext)
		})
		moved, err := snapshots.LoadTests(owned, ids, 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		if item, err := moved.ResolveContext(owned, tenant, testIDs[tenant], allowed, 1<<20); err != nil || item != nil {
			t.Fatal("moved test retained an earlier context's disclosure")
		}
		item, err := moved.ResolveContext(owned, tenant, testIDs[tenant], map[string]bool{movedContext: true}, 1<<20)
		if err != nil || item == nil || item.Scope.ContextID != movedContext || len(item.Items) != 0 {
			t.Fatal("moved test inherited old context rules")
		}
		mutate(tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `DELETE FROM tests WHERE tenant_id=$1 AND id=$2`, tenant, testIDs[tenant])
			return err
		})
		deleted, err := snapshots.LoadTests(owned, ids, 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		if item, err := deleted.ResolveContext(owned, tenant, testIDs[tenant], map[string]bool{movedContext: true}, 1<<20); err != nil || item != nil {
			t.Fatal("deleted test retained metadata")
		}
	}
}
