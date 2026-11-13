// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package entity

// SNMPInterfaceState preserves observed IF-MIB values. Each optional field
// distinguishes an unavailable column from an explicit enum value. An
// operationally down interface alone does not prove an unplanned fault.
type SNMPInterfaceState struct {
	Version     int     `json:"version"`
	OperStatus  *uint32 `json:"oper_status,omitempty"`
	AdminStatus *uint32 `json:"admin_status,omitempty"`
}

func normalizeSNMPInterfaceState(input *SNMPInterfaceState) (*SNMPInterfaceState, error) {
	if input == nil {
		return nil, nil
	}
	if input.Version != 1 || input.OperStatus == nil && input.AdminStatus == nil {
		return nil, ErrInvalidClaim
	}
	out := *input
	for _, field := range []struct {
		value **uint32
		max   uint32
	}{{&out.OperStatus, 7}, {&out.AdminStatus, 3}} {
		if *field.value == nil {
			continue
		}
		value := **field.value
		if value == 0 || value > field.max {
			return nil, ErrInvalidClaim
		}
		*field.value = &value
	}
	return &out, nil
}
