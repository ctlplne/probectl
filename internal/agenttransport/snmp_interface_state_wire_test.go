// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestSNMPInterfaceStateWireRefusesUnknownOrIncompleteFacts(t *testing.T) {
	if got, err := parseSNMPInterfaceState(nil); err != nil || got != nil {
		t.Fatal("legacy absence acquired observed state", got, err)
	}
	good := &agentv1.SnmpInterfaceState{Version: 1, OperStatus: proto.Uint32(7), AdminStatus: proto.Uint32(3)}
	if got, err := parseSNMPInterfaceState(good); err != nil || *got.OperStatus != 7 || *got.AdminStatus != 3 {
		t.Fatal("complete original enum range was narrowed", err)
	}
	for name, mutate := range map[string]func(*agentv1.SnmpInterfaceState){
		"unknown":     func(s *agentv1.SnmpInterfaceState) { s.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1}) },
		"version":     func(s *agentv1.SnmpInterfaceState) { s.Version = 2 },
		"empty":       func(s *agentv1.SnmpInterfaceState) { s.OperStatus, s.AdminStatus = nil, nil },
		"oper zero":   func(s *agentv1.SnmpInterfaceState) { s.OperStatus = proto.Uint32(0) },
		"oper range":  func(s *agentv1.SnmpInterfaceState) { s.OperStatus = proto.Uint32(8) },
		"admin zero":  func(s *agentv1.SnmpInterfaceState) { s.AdminStatus = proto.Uint32(0) },
		"admin range": func(s *agentv1.SnmpInterfaceState) { s.AdminStatus = proto.Uint32(4) },
	} {
		raw := proto.Clone(good).(*agentv1.SnmpInterfaceState)
		mutate(raw)
		if _, err := parseSNMPInterfaceState(raw); status.Code(err) != codes.InvalidArgument {
			t.Fatal("invalid interface metadata was accepted", name, err)
		}
	}
}
