// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package agenttransport

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"

	agentv1 "github.com/ctlplne/probectl/internal/gen/probectl/agent/v1"
)

func TestBMPPeerSessionWireDerivesOnlyOriginalPhysicalFacts(t *testing.T) {
	raw := make([]byte, 49)
	raw[0], raw[5], raw[48] = 3, 2, 4
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(raw)))
	copy(raw[28:32], []byte{192, 0, 2, 7})
	binary.BigEndian.PutUint32(raw[32:36], 4294967295)
	for _, name := range []string{"whole", "unknown", "LocRIB", "truncated", "canceled"} {
		t.Run(name, func(t *testing.T) {
			wire := &agentv1.BmpPeerSession{Frame: append([]byte(nil), raw...)}
			ctx := t.Context()
			switch name {
			case "unknown":
				wire.ProtoReflect().SetUnknown([]byte{0x10, 1})
			case "LocRIB":
				wire.Frame[6] = 3
			case "truncated":
				wire.Frame = wire.Frame[:48]
			case "canceled":
				var cancel func()
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			fact, err := parseBMPPeerSession(ctx, wire)
			if name != "whole" {
				if err == nil || fact != nil {
					t.Fatal("untrusted frame became typed metadata")
				}
				return
			}
			if err != nil || fact.State != "down" || fact.PeerASN != 4294967295 || fact.PeerAddress != "192.0.2.7" || !bytes.Equal(fact.RawFrame, raw) {
				t.Fatal("original physical fact was lost", err)
			}
			clear(wire.Frame)
			if !bytes.Equal(fact.RawFrame, raw) || fact.Validate() != nil {
				t.Fatal("typed metadata borrowed mutable request bytes")
			}
		})
	}
}
