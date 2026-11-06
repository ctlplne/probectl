// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package store

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/ctlplne/probectl/internal/entity"
	"github.com/ctlplne/probectl/internal/tenancy"
)

func TestInterfaceRoleFlowBindingRequiresTenantBeforeStorageAndExactIdentity(t *testing.T) {
	want := entity.Scope{TenantID: "11111111-1111-4111-8111-111111111111", ContextID: "22222222-2222-4222-8222-222222222222"}
	var reader *InterfaceRoleInputsStore
	if out, err := reader.FlowBindingsInScope(t.Context(), tenancy.Scope{}, want, entity.InterfaceRolePolicyBudget{}); !errors.Is(err, entity.ErrScopeMismatch) || out != nil {
		t.Fatal("missing tenant reached role flow binding storage", out, err)
	}
	for _, address := range []string{"192.0.2.1", "2001:db8::1"} {
		for _, protocol := range []string{"netflow5", "netflow9", "ipfix", "sflow5"} {
			for _, domain := range []string{"0", "4294967295"} {
				got, kind, id, err := parseInterfaceRoleFlowBinding(address, address+"/"+protocol+"/"+domain, "flow:"+protocol+":domain:"+domain)
				if err != nil || got != netip.MustParseAddr(address) || kind != protocol || domain == "4294967295" && id != 4294967295 || domain == "0" && id != 0 {
					t.Fatal("role flow identity lost protocol, address or complete domain", got, kind, id, err)
				}
			}
		}
	}
	for _, alias := range []string{"192.0.2.2/ipfix/0", "192.0.2.1/ipfix/00", "192.0.2.1/ipfix/4294967296", "192.0.2.1/unknown/0", "192.0.2.1/ipfix/0/extra"} {
		if out, _, _, err := parseInterfaceRoleFlowBinding("192.0.2.1", alias, "flow:ipfix:domain:0"); err == nil || out.IsValid() {
			t.Fatal("role flow binding accepted ambiguous collector identity", alias, err)
		}
	}
}
