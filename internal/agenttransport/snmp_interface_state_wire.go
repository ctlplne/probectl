// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func parseSNMPInterfaceState(state *agentv1.SnmpInterfaceState) (*entity.SNMPInterfaceState, error) {
	if state == nil {
		return nil, nil
	}
	if len(state.ProtoReflect().GetUnknown()) != 0 || state.Version != 1 || state.OperStatus == nil && state.AdminStatus == nil ||
		state.OperStatus != nil && (*state.OperStatus == 0 || *state.OperStatus > 7) ||
		state.AdminStatus != nil && (*state.AdminStatus == 0 || *state.AdminStatus > 3) {
		return nil, status.Error(codes.InvalidArgument, "unsupported SNMP interface state")
	}
	return &entity.SNMPInterfaceState{Version: int(state.Version), OperStatus: state.OperStatus, AdminStatus: state.AdminStatus}, nil
}
