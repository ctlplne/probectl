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

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestAssessmentInventoryKeepsCompleteRegistryCurrentAuthorityAndTenantIsolation(t *testing.T) {
	pool := setup(t.Context(), t)
	t.Cleanup(pool.Close)
	var tenants []string
	contextID, parentID := uuid.NewString(), uuid.NewString()
	for lane := range 2 {
		tenant, err := NewTenants(pool).Create(t.Context(), fmt.Sprintf("assessment-inventory-%d-%d", time.Now().UnixNano(), lane), "assessment")
		if err != nil {
			t.Fatal(err)
		}
		tenants = append(tenants, tenant.ID)
		inTenant(t.Context(), t, pool, tenant.ID, func(ctx context.Context, sc tenancy.Scope) error {
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
 VALUES($1,$2,$3,$4,$5,'assessment VRF')`, tenant.ID, contextID, uuid.NewString(), uuid.NewString(), tenant.ID); err != nil {
				return err
			}
			if _, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label)
 VALUES($1::uuid,$2::uuid,$3::uuid,'device',$1::uuid::text)`, tenant.ID, contextID, parentID); err != nil {
				return err
			}
			_, err := sc.Q.Exec(ctx, `INSERT INTO entities(tenant_id,context_id,id,kind,label,parent_entity_id)
 SELECT $1::uuid,$2::uuid,lpad(to_hex(n),32,'0')::uuid,'interface',$1::uuid::text||'-interface-'||n::text,$3::uuid
 FROM generate_series(1,1001) n`, tenant.ID, contextID, parentID)
			return err
		})
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`, tenants); err != nil {
			t.Error(err)
		}
	})
	refs := map[string][]ReportInventoryRef{}
	for lane, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			var visible int
			if err := sc.Q.QueryRow(ctx, `SELECT count(*) FROM entities`).Scan(&visible); err != nil || visible != 1002 {
				t.Fatal("application-role inventory RLS mixed tenants", visible, err)
			}
			checked := 0
			authorize := func(_ context.Context, record entity.ContextRecord, id string) error {
				if record.TenantID != tenant || record.ContextID != contextID || record.SiteLabel != tenant || id == "" {
					t.Fatal("inventory authorization borrowed another tenant context")
				}
				checked++
				return nil
			}
			items, err := NewEntityRegistry(pool).ClientReportInventoryInScope(ctx, sc, 32<<20, authorize)
			if err != nil || len(items) != 1002 || checked != 1002 {
				t.Fatal("complete inventory stopped at a display page or omitted authorization", len(items), checked, err)
			}
			for _, item := range items {
				if item.Entity.Scope.TenantID != tenant || item.Entity.Scope.ContextID != contextID || item.Entity.Label == tenants[1-lane] {
					t.Fatal("inventory crossed canonical tenant/context identities")
				}
				refs[tenant] = append(refs[tenant], ReportInventoryRef{ContextID: contextID, EntityID: item.Entity.ID, CreatedAt: item.Entity.CreatedAt})
			}
			if err := NewEntityRegistry(pool).RecheckReportInventoryInScope(ctx, sc, refs[tenant], 32<<20); err != nil {
				return err
			}
			replaced := append([]ReportInventoryRef{}, refs[tenant]...)
			replaced[0].CreatedAt = replaced[0].CreatedAt.Add(time.Second)
			if err := NewEntityRegistry(pool).RecheckReportInventoryInScope(ctx, sc, replaced, 32<<20); err == nil {
				t.Fatal("replacement entity creation identity borrowed an old report reference")
			}
			denied := errors.New("current inventory policy denied")
			if items, err := NewEntityRegistry(pool).ClientReportInventoryInScope(ctx, sc, 32<<20, func(context.Context, entity.ContextRecord, string) error { return denied }); !errors.Is(err, denied) || items != nil {
				t.Fatal("denied inventory returned a publishable metadata prefix", err)
			}
			foreign := tenancy.WithTenant(ctx, tenancy.ID(tenants[1-lane]))
			if items, err := NewEntityRegistry(pool).ClientReportInventoryInScope(foreign, sc, 32<<20, authorize); !errors.Is(err, entity.ErrScopeMismatch) || items != nil {
				t.Fatal("foreign context borrowed the current inventory snapshot", err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	inTenant(t.Context(), t, pool, tenants[0], func(ctx context.Context, sc tenancy.Scope) error {
		_, err := sc.Q.Exec(ctx, `DELETE FROM entities WHERE tenant_id=$1 AND context_id=$2 AND id=$3`, tenants[0], contextID, refs[tenants[0]][0].EntityID)
		return err
	})
	for lane, tenant := range tenants {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		if err := tenancy.InTenantReadSnapshot(ctx, pool, func(ctx context.Context, sc tenancy.Scope) error {
			err := NewEntityRegistry(pool).RecheckReportInventoryInScope(ctx, sc, refs[tenant], 32<<20)
			if (lane == 0 && err == nil) || (lane == 1 && err != nil) {
				t.Fatal("deleted inventory identity stayed readable or invalidated its sibling", err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
