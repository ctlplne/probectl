// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSNMPInterfaceStateKeepsObservedEnumsAndSourceFamily(t *testing.T) {
	now := time.Now().UTC()
	claim := Observation{ID: uuid.NewString(), Source: SourceKey{AgentID: "owned-agent", Kind: DeviceTarget, SourceRef: "192.0.2.1"}, Alias: AliasKey{Kind: SNMPInterfaceAlias, Value: "7"}, SourceRef: "snmp:ifIndex:7", ObservedAt: now}
	for oper := uint32(1); oper <= 7; oper++ {
		for admin := uint32(1); admin <= 3; admin++ {
			claim.SNMPInterfaceState = &SNMPInterfaceState{Version: 1, OperStatus: &oper, AdminStatus: &admin}
			got, err := claim.Normalize(now)
			if err != nil || got.SNMPInterfaceState == claim.SNMPInterfaceState || got.SNMPInterfaceState.OperStatus == &oper ||
				*got.SNMPInterfaceState.OperStatus != oper || *got.SNMPInterfaceState.AdminStatus != admin {
				t.Fatal("original state was narrowed or borrowed caller memory", oper, admin, err)
			}
		}
	}
	oper, admin := uint32(1), uint32(2)
	for _, state := range []*SNMPInterfaceState{{Version: 1, OperStatus: &oper}, {Version: 1, AdminStatus: &admin}, nil} {
		claim.SNMPInterfaceState = state
		got, err := claim.Normalize(now)
		if err != nil || state == nil && got.SNMPInterfaceState != nil || state != nil &&
			((state.OperStatus == nil) != (got.SNMPInterfaceState.OperStatus == nil) || (state.AdminStatus == nil) != (got.SNMPInterfaceState.AdminStatus == nil)) {
			t.Fatal("unavailable state became an observation", err)
		}
	}
	badOper, badAdmin := uint32(8), uint32(4)
	for name, state := range map[string]*SNMPInterfaceState{
		"empty": {Version: 1}, "version": {Version: 2, OperStatus: &oper},
		"zero":        {Version: 1, OperStatus: new(uint32)},
		"oper range":  {Version: 1, OperStatus: &badOper},
		"admin range": {Version: 1, AdminStatus: &badAdmin},
	} {
		claim.SNMPInterfaceState = state
		if _, err := claim.Normalize(now); !errors.Is(err, ErrInvalidClaim) {
			t.Fatal("invalid interface state accepted", name, err)
		}
	}
	claim.SNMPInterfaceState = &SNMPInterfaceState{Version: 1, OperStatus: &oper}
	claim.Alias = AliasKey{Kind: AddressAlias, Value: "192.0.2.1"}
	claim.SourceRef = "snmp:configured-target"
	if _, err := claim.Normalize(now); !errors.Is(err, ErrInvalidClaim) {
		t.Fatal("configured-target address borrowed interface state authority", err)
	}
}
