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

	"github.com/ctlplne/probectl/internal/entity"
	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestICMPEgressWireRefusesMissingOrUnknownMetadata(t *testing.T) {
	witness := &agentv1.IcmpEgressWitness{Interface: "eth0", Source: "192.0.2.3", PeerMac: "02:00:00:00:00:04", Transmitted: 3}
	raw := &agentv1.IcmpMeasurement{Version: entity.ICMPVersionEgress, Egress: witness}
	got, err := parseICMPMeasurement(raw)
	want := entity.ICMPEgressWitness{Interface: "eth0", Source: "192.0.2.3", PeerMAC: "02:00:00:00:00:04", Transmitted: 3}
	if err != nil || got.Egress == nil || *got.Egress != want {
		t.Fatal("the receiver lost the supplied egress witness", got, err)
	}
	raw.Version = 3
	if _, err := parseICMPMeasurement(raw); status.Code(err) != codes.InvalidArgument {
		t.Fatal("a legacy message claimed an egress witness", err)
	}
	raw.Version = entity.ICMPVersionEgress
	raw.Egress = nil
	if _, err := parseICMPMeasurement(raw); status.Code(err) != codes.InvalidArgument {
		t.Fatal("a version 4 message omitted its egress witness", err)
	}
	raw.Egress = witness
	witness.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
	if _, err := parseICMPMeasurement(raw); status.Code(err) != codes.InvalidArgument {
		t.Fatal("unsupported evidence inside the witness was accepted", err)
	}
}

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

func TestICMPRoundTripWireRefusesUnknownSampleFieldsAndKeepsEmptyPresence(t *testing.T) {
	for _, samples := range [][]uint64{nil, {0, 17, 9007199254740993}} {
		raw := &agentv1.IcmpMeasurement{Version: 3, RoundTrips: &agentv1.IcmpRoundTrips{Nanos: samples}}
		result, err := parseICMPMeasurement(raw)
		if err != nil || result.RoundTrips == nil || result.RoundTrips.Nanos == nil || len(result.RoundTrips.Nanos) != len(samples) {
			t.Fatal("original RTT presence/population changed", err)
		}
		for index, value := range samples {
			if result.RoundTrips.Nanos[index] != value {
				t.Fatal("original RTT precision lost")
			}
		}
		raw.RoundTrips.ProtoReflect().SetUnknown([]byte{0x98, 0x06, 1})
		if _, err := parseICMPMeasurement(raw); status.Code(err) != codes.InvalidArgument {
			t.Fatal("unknown RTT metadata was accepted as complete evidence", err)
		}
	}
	legacy, err := parseICMPMeasurement(&agentv1.IcmpMeasurement{Version: 1})
	if err != nil || legacy.RoundTrips != nil {
		t.Fatal("legacy receipt gained invented latency", err)
	}
}
