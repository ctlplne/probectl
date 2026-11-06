// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"context"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func extendedRouteFrameForTest(length int) []byte {
	attribute := make([]byte, length-23)
	attribute[0], attribute[1] = 0xd0, 255
	binary.BigEndian.PutUint16(attribute[2:4], uint16(len(attribute)-4))
	for i := 4; i < len(attribute); i++ {
		attribute[i] = byte(i)
	}
	return endOfRIBFrameForTest(nil, attribute, nil)
}
func TestBMPUpdateFrameUsesReceivingCapabilityAndKeepsFullProtocolMaximum(t *testing.T) {
	plain := routeOpenForTest(nil, false)
	extended := routeOpenForTest([]byte{6, 0}, false)
	budget := UpdateFrameBudget{16 << 20, 16 << 20}
	for _, view := range []BMPRouteView{BMPAdjRIBInPrePolicy, BMPAdjRIBInPostPolicy, BMPAdjRIBOutPrePolicy, BMPAdjRIBOutPostPolicy} {
		for _, direction := range []struct {
			sent, received []byte
			allowed        bool
		}{{plain, plain, false}, {extended, extended, true}, {extended, plain, view == BMPAdjRIBInPrePolicy || view == BMPAdjRIBInPostPolicy}, {plain, extended, view == BMPAdjRIBOutPrePolicy || view == BMPAdjRIBOutPostPolicy}} {
			source := PeerUp{Header: BMPRouteViewHeader{View: view}, SentOpen: direction.sent, ReceivedOpen: direction.received}
			for _, size := range []int{4096, 4097, 65535} {
				raw := extendedRouteFrameForTest(size)
				got, err := parseBMPRouteUpdateFrame(t.Context(), raw, source, budget)
				if size > 4096 && !direction.allowed {
					if !errors.Is(err, ErrBGPUpdateFrame) || !reflect.DeepEqual(got, UpdateFrame{}) {
						t.Fatal("extended UPDATE guessed receiver permission from sender capability", view, size, err)
					}
					continue
				}
				if err != nil || len(got.Attributes) != 1 || len(got.Attributes[0].Value) != size-27 || got.Attributes[0].Value[0] != 4 || got.HasEndOfRIB {
					t.Fatal("source UPDATE lost the complete protocol-sized attribute", view, size, err)
				}
				clear(raw)
				if got.Attributes[0].Value[0] != 4 {
					t.Fatal("source UPDATE retained borrowed payload")
				}
			}
		}
	}
	open := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 6, 0}, false)
	source := PeerUp{Header: BMPRouteViewHeader{View: BMPLocRIB}, SentOpen: open, ReceivedOpen: open}
	if out, err := parseBMPRouteUpdateFrame(t.Context(), extendedRouteFrameForTest(65535), source, budget); err != nil || len(out.Attributes[0].Value) != 65535-27 {
		t.Fatal("Loc-RIB refused its complete declared extended encoding", err)
	}
}

func TestBMPUpdateFrameRefusesMissingMalformedSourceAndWholeOperationAdmission(t *testing.T) {
	good := routeOpenForTest([]byte{65, 4, 0, 0, 0, 1, 6, 0}, false)
	raw := extendedRouteFrameForTest(4097)
	budget := UpdateFrameBudget{16 << 20, 16 << 20}
	for _, source := range []PeerUp{
		{}, {Header: BMPRouteViewHeader{View: BMPAdjRIBInPrePolicy}, SentOpen: good},
		{Header: BMPRouteViewHeader{View: BMPAdjRIBInPrePolicy}, SentOpen: routeOpenForTest([]byte{6, 1, 0}, false), ReceivedOpen: good},
		{Header: BMPRouteViewHeader{View: BMPLocRIB}, SentOpen: good, ReceivedOpen: routeOpenForTest([]byte{65, 4, 0, 0, 0, 2, 6, 0}, false)},
		{Header: BMPRouteViewHeader{View: BMPLocRIB}, SentOpen: routeOpenForTest([]byte{6, 0}, false), ReceivedOpen: routeOpenForTest([]byte{6, 0}, false)},
	} {
		if out, err := parseBMPRouteUpdateFrame(t.Context(), raw, source, budget); !errors.Is(err, ErrRouteCapabilities) || !reflect.DeepEqual(out, UpdateFrame{}) {
			t.Fatal("unknown source OPEN or malformed capability exposed an UPDATE", err)
		}
	}
	source := PeerUp{Header: BMPRouteViewHeader{View: BMPLocRIB}, SentOpen: good, ReceivedOpen: good}
	for _, limited := range []UpdateFrameBudget{{0, 1 << 20}, {1 << 20, 0}, {128 * int64(len(raw)), 8 * int64(len(raw))}} {
		if out, err := parseBMPRouteUpdateFrame(t.Context(), raw, source, limited); !errors.Is(err, ErrBGPUpdateFrameBudget) || !reflect.DeepEqual(out, UpdateFrame{}) {
			t.Fatal("source UPDATE omitted combined OPEN and frame admission", err)
		}
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if out, err := parseBMPRouteUpdateFrame(canceled, raw, source, budget); !errors.Is(err, context.Canceled) || !reflect.DeepEqual(out, UpdateFrame{}) {
		t.Fatal("source UPDATE ignored cancellation", err)
	}
}
