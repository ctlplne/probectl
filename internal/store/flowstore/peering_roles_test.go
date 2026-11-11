// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flowstore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

type peeringRoleScope interface {
	ForRouter(context.Context, entity.Scope, string, time.Time, int64) (*InterfaceRoleQueryData, error)
}

func TestPeeringRoleScopeKeepsWholeCurrentOwnershipBeforeRouterSelection(t *testing.T) {
	const red, blue = "11111111-1111-4111-8111-111111111111", "66666666-6666-4666-8666-666666666666"
	at := time.Now().UTC().Truncate(time.Microsecond)
	for _, tenant := range []string{red, blue} {
		ctx := tenancy.WithTenant(t.Context(), tenancy.ID(tenant))
		rows := roleQueryFixture(tenant, at)
		sibling := rows[0]
		sibling.ContextID, sibling.RouterID, sibling.Exporter = "77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888", "192.0.2.2"
		sibling.ValidUntil = at.Add(10 * time.Second)
		rows = append(rows, sibling)
		full, err := NewInterfaceRoleQueryData(ctx, tenant, at, rows, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		selector, present := any(full).(peeringRoleScope)
		if !present {
			t.Fatal("peering role scope cannot select an owned router from complete current metadata")
		}
		selected, err := selector.ForRouter(ctx, rows[0].Scope, rows[0].RouterID, at.Add(time.Second), 1<<20)
		if err != nil || selected == nil || len(selected.rows) != 2 || !selected.asOf.Equal(at) {
			t.Fatal("peering role selection lost complete interfaces or renewed the original clock", err)
		}
		own := Row{TenantID: tenant, Exporter: rows[0].Exporter, Protocol: "ipfix", ObsDomain: rows[0].Domain, InIf: 7}
		other := own
		other.Exporter = sibling.Exporter
		if selected.valueForRow(own, false) != string(entity.InterfaceRoleTransit) || selected.valueForRow(other, false) != string(entity.InterfaceRoleOther) || full.valueForRow(other, false) != string(entity.InterfaceRoleTransit) {
			t.Fatal("peering role scope included another context/router or mutated the full source")
		}
		selected.rows[0].Sources[0] = "changed selected copy"
		if full.rows[0].Sources[0] == "changed selected copy" {
			t.Fatal("peering role scope aliases complete source metadata")
		}
		foreign := rows[0].Scope
		foreign.TenantID = blue
		if tenant == blue {
			foreign.TenantID = red
		}
		if got, err := selector.ForRouter(ctx, foreign, rows[0].RouterID, at, 1<<20); !errors.Is(err, ErrInterfaceRoleQueryScope) || got != nil {
			t.Fatal("foreign peering scope reused current role metadata", err)
		}
		if got, err := selector.ForRouter(ctx, rows[0].Scope, rows[0].RouterID, sibling.ValidUntil, 1<<20); !errors.Is(err, ErrInterfaceRoleQueryScope) || got != nil {
			t.Fatal("peering selection pruned expired full-source authority", err)
		}
		if got, err := selector.ForRouter(ctx, rows[0].Scope, rows[0].RouterID, at, 4096); !errors.Is(err, ErrExplorerBudget) || got != nil {
			t.Fatal("peering role scope returned partial unadmitted metadata", err)
		}
	}
}
