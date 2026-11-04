// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"context"
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestQueryViewCurrentAccessIsScopedAndIndependentOfFrozenDefinition(t *testing.T) {
	store := NewMemoryQueryViewStore(nil, 0)
	// Same-ID component fixture targets partition selection, not a source grant.
	for _, tenant := range []string{"red", "blue"} {
		store.byTenant[tenant] = map[string]SavedQueryView{"same-id": {ID: "same-id", TenantID: tenant, OwnerID: tenant + "-owner", Version: "9007199254740993", Definition: QueryViewDefinition{Visibility: "private", Name: "later invalid definition", TagIDs: map[string]string{"tag.deleted": "old-id"}}}}
	}
	for _, tenant := range []string{"red", "blue"} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		item, err := store.GetQueryViewAccess(ctx, tenant, tenant+"-owner", "same-id")
		if err != nil || item.TenantID != tenant || item.OwnerID != tenant+"-owner" || item.Version != "9007199254740993" {
			t.Fatal("current access lost tenant ownership or exact version", err)
		}
		item.OwnerID = "caller-mutation"
		if current, err := store.GetQueryViewAccess(ctx, tenant, tenant+"-owner", "same-id"); err != nil || current.OwnerID != tenant+"-owner" {
			t.Fatal("caller mutation changed source visibility", err)
		}
		if _, err := store.GetQueryViewAccess(ctx, tenant, "viewer", "same-id"); !errors.Is(err, ErrQueryViewNotFound) {
			t.Fatal("private source metadata reached another reader", err)
		}
		shared := store.byTenant[tenant]["same-id"]
		shared.Definition.Visibility = "tenant"
		store.byTenant[tenant]["same-id"] = shared
		if item, err := store.GetQueryViewAccess(ctx, tenant, "viewer", "same-id"); err != nil || item.Visibility != "tenant" || item.OwnerID != tenant+"-owner" {
			t.Fatal("current sharing required reinterpreting changed query text", err)
		}
		shared.Definition.Visibility = "private"
		store.byTenant[tenant]["same-id"] = shared
		if _, err := store.GetQueryViewAccess(ctx, tenant, "viewer", "same-id"); !errors.Is(err, ErrQueryViewNotFound) {
			t.Fatal("revoked source sharing retained metadata access", err)
		}
	}
}

func TestQueryViewCurrentAccessRefusesMissingMismatchedAndMalformedScope(t *testing.T) {
	store := NewMemoryQueryViewStore(nil, 0)
	ctx := tenancy.WithTenant(t.Context(), "red")
	for _, request := range []struct {
		ctx               context.Context
		tenant, owner, id string
	}{{t.Context(), "red", "owner", "same"}, {ctx, "blue", "owner", "same"}, {ctx, "red", "", "same"}, {ctx, "red", "owner", ""}, {ctx, "red", "owner", "missing"}} {
		if item, err := store.GetQueryViewAccess(request.ctx, request.tenant, request.owner, request.id); !errors.Is(err, ErrQueryViewNotFound) || item != (QueryViewAccess{}) {
			t.Fatal("missing or unscoped source metadata was exposed", err)
		}
	}
	base := SavedQueryView{ID: "same", TenantID: "red", OwnerID: "owner", Version: "1", Definition: QueryViewDefinition{Visibility: "private"}}
	for _, change := range []func(*SavedQueryView){func(v *SavedQueryView) { v.ID = "other" }, func(v *SavedQueryView) { v.TenantID = "blue" }, func(v *SavedQueryView) { v.OwnerID = "" }, func(v *SavedQueryView) { v.Version = "1e6" }, func(v *SavedQueryView) { v.Definition.Visibility = "invalid" }} {
		item := base
		change(&item)
		store.byTenant["red"] = map[string]SavedQueryView{"same": item}
		if item, err := store.GetQueryViewAccess(ctx, "red", "owner", "same"); !errors.Is(err, ErrQueryViewNotFound) || item != (QueryViewAccess{}) {
			t.Fatal("malformed current metadata granted source visibility", err)
		}
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := store.GetQueryViewAccess(canceled, "red", "owner", "same"); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled source visibility read ran", err)
	}
}
