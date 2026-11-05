// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"errors"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestInterfaceRoleCASUsesExactIdentityAndDecimalRevision(t *testing.T) {
	id := "11111111-1111-4111-8111-111111111111"
	for _, revision := range []string{"1", "9007199254740993", "9223372036854775807"} {
		if version, err := interfaceRoleExpectedVersion(id, revision); err != nil || version <= 0 {
			t.Fatal("valid exact role version refused", revision, err)
		}
	}
	if version, err := interfaceRoleExpectedVersion("", "0"); err != nil || version != 0 {
		t.Fatal("new configuration lost its absent identity", err)
	}
	for _, pair := range [][2]string{{id, "0"}, {"", "1"}, {id, "01"}, {id, "+1"}, {id, "-1"}, {id, "9223372036854775808"}, {"00000000-0000-0000-0000-000000000000", "1"}} {
		if _, err := interfaceRoleExpectedVersion(pair[0], pair[1]); !errors.Is(err, entity.ErrInterfaceRoleConflict) {
			t.Fatal("ambiguous or missing role incarnation/version accepted", pair, err)
		}
	}
}

func TestInterfaceRoleStorageRequiresTenantBeforeAnyQuery(t *testing.T) {
	sc := tenancy.Scope{Tenant: tenancy.ID("11111111-1111-4111-8111-111111111111")}
	store := InterfaceRoleConfiguration{}
	for _, ctx := range []struct{ tenant string }{{""}, {"22222222-2222-4222-8222-222222222222"}} {
		bound := t.Context()
		if ctx.tenant != "" {
			bound = tenancy.WithTenant(bound, tenancy.ID(ctx.tenant))
		}
		if _, err := store.Policy(bound, sc, "33333333-3333-4333-8333-333333333333", entity.InterfaceRolePolicyBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}); !errors.Is(err, tenancy.ErrNoTenant) {
			t.Fatal("role policy reached an unscoped querier", err)
		}
		if _, err := store.PutOverride(bound, sc, "33333333-3333-4333-8333-333333333333", "bad-interface", "", "0", "bad-role"); !errors.Is(err, tenancy.ErrNoTenant) {
			t.Fatal("override validation preceded mandatory tenant context", err)
		}
	}
}
