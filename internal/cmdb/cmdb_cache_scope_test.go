// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cmdb

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/tenancy"
)

// Implements only Provider, deliberately lacking NetBox's optional scope hook.
type tenantContextProvider struct{ calls map[string]int }

func (*tenantContextProvider) Name() string { return "tenant-context-fixture" }
func (p *tenantContextProvider) Lookup(ctx context.Context, _ string) ([]CI, error) {
	tenant, ok := tenancy.FromContext(ctx)
	if !ok {
		return nil, ErrTenantBinding
	}
	p.calls[tenant.String()]++
	return []CI{{SysID: "same-ci-id", Name: "private-" + tenant.String()}}, nil
}

func TestResolverEveryProviderCacheRequiresTenantScope(t *testing.T) {
	provider := &tenantContextProvider{calls: map[string]int{}}
	resolver := NewResolver(provider, time.Hour)
	for range 2 {
		for _, tenant := range []string{netBoxTenantA, netBoxTenantB} {
			ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
			cis, err := resolver.Lookup(ctx, "SHARED.EXAMPLE")
			if err != nil || len(cis) != 1 || cis[0].SysID != "same-ci-id" || cis[0].Name != "private-"+tenant {
				t.Fatal("generic cache reused another tenant's CI", err)
			}
		}
	}
	if provider.calls[netBoxTenantA] != 1 || provider.calls[netBoxTenantB] != 1 {
		t.Fatal("paired cache proof did not exercise both independent warm entries")
	}
	for _, ctx := range []context.Context{
		t.Context(),
		tenancy.WithTenant(t.Context(), tenancy.ID("not-a-uuid")),
		tenancy.WithTenant(t.Context(), tenancy.ID("00000000-0000-0000-0000-000000000000")),
	} {
		for _, key := range []string{"shared.example", ""} {
			if cis, err := resolver.Lookup(ctx, key); !errors.Is(err, ErrTenantBinding) || cis != nil {
				t.Fatal("missing or invalid tenant reached a cached CI or provider", err)
			}
		}
	}
	if len(provider.calls) != 2 || provider.calls[netBoxTenantA] != 1 || provider.calls[netBoxTenantB] != 1 {
		t.Fatal("unbound cache lookup reached source I/O")
	}
}
