// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agent

import (
	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func encodeSNMPInterfaceState(state *entity.SNMPInterfaceState) *agentv1.SnmpInterfaceState {
	if state == nil {
		return nil
	}
	return &agentv1.SnmpInterfaceState{Version: uint32(state.Version), OperStatus: state.OperStatus, AdminStatus: state.AdminStatus}
}
