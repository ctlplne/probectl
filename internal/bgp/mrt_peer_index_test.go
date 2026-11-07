// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package bgp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func mrtRecordForTest(subtype uint16, body []byte) []byte {
	raw := make([]byte, 12, 12+len(body))
	binary.BigEndian.PutUint32(raw[:4], ^uint32(0))
	binary.BigEndian.PutUint16(raw[4:6], 13)
	binary.BigEndian.PutUint16(raw[6:8], subtype)
	binary.BigEndian.PutUint32(raw[8:12], uint32(len(body)))
	return append(raw, body...)
}

func TestMRTPeerIndexKeepsWholeWirePopulationBinaryIdentityAndEmptySource(t *testing.T) {
	view := bytes.Repeat([]byte{255}, 65535)
	body := make([]byte, 6)
	binary.BigEndian.PutUint32(body[:4], ^uint32(0))
	binary.BigEndian.PutUint16(body[4:6], uint16(len(view)))
	body = append(body, view...)
	body = binary.BigEndian.AppendUint16(body, 65535)
	address := netip.MustParseAddr("::ffff:192.0.2.1").As16()
	for i := range 65535 {
		body = append(body, 3)
		body = binary.BigEndian.AppendUint32(body, uint32(i))
		body = append(body, address[:]...)
		body = binary.BigEndian.AppendUint32(body, ^uint32(0))
	}
	raw := mrtRecordForTest(1, body)
	budget := UpdateFrameBudget{MemoryBytes: 512 << 20, WorkUnits: 512 << 20}
	got, err := DecodeMRTPeerIndex(t.Context(), raw, budget)
	if err != nil || len(got.Peers) != 65535 || !bytes.Equal(got.ViewName, view) || got.CollectorIdentifier != ^uint32(0) || got.ObservedUnixNanos != int64(^uint32(0))*1_000_000_000 {
		t.Fatal("MRT peer source lost complete original wire identity or population", len(got.Peers), err)
	}
	if last := got.Peers[len(got.Peers)-1]; last.ASN != ^uint32(0) || last.BGPIdentifier != 65534 || !last.Address.Is4In6() {
		t.Fatal("MRT peer source narrowed original address, ASN or identifier", last)
	}
	clear(raw)
	if got.ViewName[0] != 255 || got.Peers[0].BGPIdentifier != 0 {
		t.Fatal("MRT source borrowed input bytes or confused explicit zero")
	}
	empty, err := DecodeMRTPeerIndex(t.Context(), mrtRecordForTest(1, make([]byte, 8)), budget)
	if err != nil || empty.Peers == nil || len(empty.Peers) != 0 || empty.ViewName == nil || empty.CollectorIdentifier != 0 {
		t.Fatal("MRT empty source invented or lost peer presence", empty, err)
	}
}

func TestMRTPeerIndexRefusesWholeLateMalformedUnadmittedAndCanceledRecords(t *testing.T) {
	budget := UpdateFrameBudget{MemoryBytes: 1 << 20, WorkUnits: 1 << 20}
	body := []byte{0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 192, 0, 2, 1, 255, 255, 255, 255}
	valid := mrtRecordForTest(1, body)
	for _, raw := range [][]byte{nil, valid[:11], valid[:len(valid)-1], append(bytes.Clone(valid), 0), mrtRecordForTest(2, body), mrtRecordForTest(1, append(bytes.Clone(body), 0))} {
		if got, err := DecodeMRTPeerIndex(t.Context(), raw, budget); !errors.Is(err, ErrMRTRecord) || got.Peers != nil || got.ViewName != nil {
			t.Fatal("MRT source exposed partial peers after whole-record refusal", got, err)
		}
	}
	bad := bytes.Clone(body)
	bad[8] = 0x80
	if got, err := DecodeMRTPeerIndex(t.Context(), mrtRecordForTest(1, bad), budget); !errors.Is(err, ErrMRTRecord) || got.Peers != nil {
		t.Fatal("MRT source accepted undefined peer type", got, err)
	}
	if got, err := DecodeMRTPeerIndex(t.Context(), valid, UpdateFrameBudget{MemoryBytes: 1, WorkUnits: 1}); !errors.Is(err, ErrMRTBudget) || got.Peers != nil {
		t.Fatal("MRT source bypassed whole operation admission", got, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := DecodeMRTPeerIndex(ctx, valid, budget); !errors.Is(err, context.Canceled) {
		t.Fatal("MRT source ignored cancellation", err)
	}
}

func FuzzMRTPeerIndex(f *testing.F) {
	f.Add(mrtRecordForTest(1, make([]byte, 8)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeMRTPeerIndex(t.Context(), raw, UpdateFrameBudget{MemoryBytes: 4 << 20, WorkUnits: 4 << 20})
	})
}
