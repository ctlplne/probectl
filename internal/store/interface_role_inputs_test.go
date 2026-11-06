// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestInterfaceRoleInputsRequireTenantBeforeStorageAndCanonicalPeerValues(t *testing.T) {
	scope := entity.Scope{TenantID: "11111111-1111-4111-8111-111111111111", ContextID: "22222222-2222-4222-8222-222222222222"}
	var reader *InterfaceRoleInputsStore
	got, err := reader.Load(t.Context(), scope, "33333333-3333-4333-8333-333333333333", entity.InterfaceRolePolicyBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
	if !errors.Is(err, entity.ErrScopeMismatch) || !reflect.DeepEqual(got, InterfaceRoleInputs{}) {
		t.Fatal("missing tenant reached role source storage", err)
	}
	got, err = reader.Load(tenancy.WithTenant(t.Context(), "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), scope, "33333333-3333-4333-8333-333333333333", entity.InterfaceRolePolicyBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20})
	if !errors.Is(err, entity.ErrScopeMismatch) || !reflect.DeepEqual(got, InterfaceRoleInputs{}) {
		t.Fatal("foreign tenant reached role source storage", err)
	}
	for _, address := range []string{"198.51.100.7", "2001:db8::7"} {
		got, asn, err := parseInterfaceRolePeer(address+"/as4294967295", "bmp:router:owned:peer-asn:4294967295", "owned")
		if err != nil || got != netip.MustParseAddr(address) || asn != 4294967295 {
			t.Fatal("canonical peer lost complete positive ASN/address", got, asn, err)
		}
	}
	for _, alias := range []string{"198.51.100.7/as0", "198.51.100.7/as4294967296", "198.51.100.7/as064496", "::ffff:192.0.2.7/as64496", "ff02::1/as64496", "2001:0db8::7/as64496", "198.51.100.7/as64496/trailer"} {
		if _, _, err := parseInterfaceRolePeer(alias, "bmp:router:owned:peer-asn:64496", "owned"); !errors.Is(err, entity.ErrInvalidClaim) {
			t.Fatal("malformed peer values entered role inputs", alias, err)
		}
	}
	if _, _, err := parseInterfaceRolePeer("198.51.100.7/as64496", "bmp:router:foreign:peer-asn:64496", "owned"); !errors.Is(err, entity.ErrInvalidClaim) {
		t.Fatal("peer provenance chose a different router")
	}
}

// The convenience snapshot wrapper is a fixture API; shipping callers retain
// their authorized snapshot and use LoadInScope.
// Load uses FORCE RLS, the current tenant router, one REPEATABLE READ time and
// transaction-wide silo relation locks. Raw IP/ifIndex never chooses ownership.
// Missing automatic observations preserve an owned manual override; absent or
// foreign canonical interfaces fail closed before reading any source facts.
func (s *InterfaceRoleInputsStore) Load(ctx context.Context, scope entity.Scope, interfaceID string, budget entity.InterfaceRolePolicyBudget) (InterfaceRoleInputs, error) {
	none := InterfaceRoleInputs{}
	want, err := scope.Normalize()
	tenant, ok := tenancy.FromContext(ctx)
	if err != nil || !ok || tenant.String() != want.TenantID {
		return none, entity.ErrScopeMismatch
	}
	id, err := validRegistryUUID(interfaceID)
	if err != nil {
		return none, err
	}
	if s == nil || s.pool == nil {
		return none, ErrEntityRegistryUnavailable
	}
	if budget.MemoryBytes <= 0 || budget.WorkUnits <= 0 {
		return none, entity.ErrInterfaceRoleBudget
	}
	var out InterfaceRoleInputs
	err = tenancy.InTenantReadSnapshot(ctx, s.pool, func(ctx context.Context, sc tenancy.Scope) error {
		var readErr error
		out, readErr = s.LoadInScope(ctx, sc, want, id, budget)
		return readErr
	})
	if err != nil {
		return none, err
	}
	if err := ctx.Err(); err != nil {
		return none, err
	}
	return out, nil
}
