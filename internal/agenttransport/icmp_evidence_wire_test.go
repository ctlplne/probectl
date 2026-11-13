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

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestICMPMeasurementWireRefusesUnknownMetadataFields(t *testing.T) {
	if got, err := parseICMPMeasurement(nil); err != nil || got != nil {
		t.Fatal("legacy absence acquired health authority", got, err)
	}
	raw := &agentv1.IcmpMeasurement{Version: 1}
	raw.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
	if _, err := parseICMPMeasurement(raw); status.Code(err) != codes.InvalidArgument {
		t.Fatal("unknown metadata was accepted as complete current evidence", err)
	}
	for _, item := range []*agentv1.IcmpNetworkError{nil, {Responder: "192.0.2.1"}} {
		if item != nil {
			item.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
		}
		if _, err := parseICMPMeasurement(&agentv1.IcmpMeasurement{Version: 2, NetworkErrors: []*agentv1.IcmpNetworkError{item}}); status.Code(err) != codes.InvalidArgument {
			t.Fatal("incomplete network error was accepted", err)
		}
	}
}
