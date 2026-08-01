// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"os"
	"testing"
	"time"
)

func TestOfflineInteropFlowCapturesDecodeAndNormalize(t *testing.T) {
	if _, err := os.ReadFile("../../test/interop/fixtures/flow-captures.json"); err != nil {
		t.Fatal(err)
	}

	d := NewDecoder(time.Hour, 128)
	unix := uint32(testTime.Unix())
	seen := map[string]bool{}

	decode := func(label string, packets ...[]byte) {
		t.Helper()
		for _, pkt := range packets {
			recs, misses, err := d.Decode(pkt, exporter, testTime)
			if err != nil || misses != 0 {
				t.Fatalf("%s decode: misses=%d err=%v", label, misses, err)
			}
			for _, r := range recs {
				r.TenantID = "tenant-a"
				r.AgentID = "flow-agent-1"
				pb := r.ToProto()
				if pb.GetTenantId() != "tenant-a" || pb.GetAgentId() != "flow-agent-1" {
					t.Fatalf("%s record not tenant-stamped: %+v", label, pb)
				}
				if pb.GetBytesScaled() == 0 && r.Bytes != 0 {
					t.Fatalf("%s lost scaled bytes: %+v", label, pb)
				}
				seen[r.Protocol] = true
			}
		}
	}

	decode("netflow-v5", buildNF5(60_000, unix, 0x4002, []nf5rec{{
		src: [4]byte{10, 0, 0, 1}, dst: [4]byte{10, 0, 0, 2}, pkts: 10, bytes: 1000, proto: 6, sport: 1234, dport: 443,
	}}))
	row := nf9V4Row([4]byte{172, 16, 0, 1}, [4]byte{172, 16, 0, 2}, 53, 33000, 17, 512, 4, 10_000, 20_000)
	decode("netflow-v9-template", buildNF9Template(100_000, unix, 7, 260, nf9V4Fields))
	decode("netflow-v9-data", buildNF9Data(100_000, unix, 7, 260, [][]byte{row}))
	ipfixRow := (&wireBuf{}).
		raw([]byte{192, 0, 2, 1}).raw([]byte{198, 51, 100, 2}).
		u16(443).u16(55000).u8(6).u64(123_456).u64(789).b
	decode("ipfix", ipfixMsg(unix, 9,
		ipfixTemplateSet(2, 300, 0, []ipfixField{{ID: ieIPv4Src, Len: 4}, {ID: ieIPv4Dst, Len: 4}, {ID: ieSrcPort, Len: 2}, {ID: ieDstPort, Len: 2}, {ID: ieProtocol, Len: 1}, {ID: ieInBytes, Len: 8}, {ID: ieInPackets, Len: 8}}),
		ipfixDataSet(300, ipfixRow)))
	hdr := buildEthIPv4TCP(100, [4]byte{10, 1, 1, 1}, [4]byte{192, 0, 2, 9}, 443, 51000, 0x12, 6)
	decode("sflow", buildSFlowRaw(1024, 5, 7, hdr, false, true))

	for _, proto := range []string{ProtoNetFlow5, ProtoNetFlow9, ProtoIPFIX, ProtoSFlow5} {
		if !seen[proto] {
			t.Fatalf("offline flow replay missed %s; seen=%v", proto, seen)
		}
	}
	if _, _, err := d.Decode([]byte{0xde, 0xad, 0xbe, 0xef}, exporter, testTime); err == nil {
		t.Fatal("malformed flow replay was accepted")
	}
}
