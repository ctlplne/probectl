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

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestEntityContextPolicyAttributesComeFromTenantScopedStore(t *testing.T) {
	ctx := context.Background()
	pool := setup(ctx, t)
	defer pool.Close()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	a, err := NewTenants(pool).Create(ctx, "entity-policy-a-"+suffix, "A")
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewTenants(pool).Create(ctx, "entity-policy-b-"+suffix, "B")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM tenants WHERE id=ANY($1::uuid[])`,
			[]string{a.ID, b.ID}); err != nil {
			t.Errorf("remove policy fixture tenants: %v", err)
		}
	}()
	sharedContext := uuid.NewString()
	for _, fixture := range []struct{ tenant, site, vrf string }{
		{a.ID, "West DC", "A-private"},
		{b.ID, "East DC", "B-private"},
	} {
		inTenant(ctx, t, pool, fixture.tenant, func(ctx context.Context, sc tenancy.Scope) error {
			_, err := sc.Q.Exec(ctx, `INSERT INTO entity_contexts
				(tenant_id,id,site_id,vrf_id,site_label,vrf_label)
				VALUES ($1,$2,$3,$4,$5,$6)`, fixture.tenant, sharedContext,
				uuid.NewString(), uuid.NewString(), fixture.site, fixture.vrf)
			return err
		})
		got, err := NewEntityRegistry(pool).GetEntityContext(
			tenancy.WithTenant(ctx, tenancy.ID(fixture.tenant)),
			entity.Scope{TenantID: fixture.tenant, ContextID: sharedContext})
		if err != nil || got.TenantID != fixture.tenant || got.ContextID != sharedContext ||
			got.SiteLabel != fixture.site || got.VRFLabel != fixture.vrf ||
			got.SiteID == "" || got.VRFID == "" {
			t.Fatalf("tenant policy attributes = %+v, %v", got, err)
		}
	}
	_, err = NewEntityRegistry(pool).GetEntityContext(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: b.ID, ContextID: sharedContext})
	if !errors.Is(err, entity.ErrScopeMismatch) {
		t.Fatalf("cross-tenant policy lookup must fail closed, got %v", err)
	}
	_, err = NewEntityRegistry(pool).GetEntityContext(
		tenancy.WithTenant(ctx, tenancy.ID(a.ID)),
		entity.Scope{TenantID: a.ID, ContextID: uuid.NewString()})
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("unknown context must not fabricate policy attributes: %v", err)
	}
}
