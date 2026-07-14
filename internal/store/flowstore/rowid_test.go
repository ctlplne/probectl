// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flowstore

import (
	"context"
	"testing"
	"time"
)

// CORRECT-001: flowRowID is the ReplacingMergeTree dedup key. A redelivered
// identical row must hash identically (so the duplicate collapses); any field
// that distinguishes two real flows must change the id (so real traffic is
// never collapsed).
func TestFlowRowIDDedupKey(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0).UTC()
	base := Row{
		TenantID: "t-a", AgentID: "agent-1", Exporter: "10.0.0.1", ObsDomain: 1,
		Protocol: "netflow5", TS: ts, StartTS: ts.Add(-30 * time.Second),
		SrcAddr: "10.1.1.1", DstAddr: "10.2.2.2", SrcPort: 1234, DstPort: 443,
		Transport: "tcp", NetType: "ipv4", InIf: 2, OutIf: 5, VLAN: 100, ToS: 46,
		TCPFlags: 0x12, NextHop: "10.0.0.254",
		Bytes: 1500, Packets: 3, Sampling: 64, BytesScaled: 96_000, PacketsScaled: 192,
		SrcASN: 64500, SrcASName: "SRC-NET", SrcCountry: "US",
		DstASN: 64501, DstASName: "DST-NET", DstCountry: "DE",
	}

	a, b := flowRowID(base), flowRowID(base)
	if a != b {
		t.Fatal("identical rows must produce the same dedup id")
	}

	// Each distinguishing field must change the id.
	for name, mutate := range map[string]func(*Row){
		"tenant":       func(r *Row) { r.TenantID = "t-b" },
		"agent":        func(r *Row) { r.AgentID = "agent-2" },
		"exporter":     func(r *Row) { r.Exporter = "10.0.0.9" },
		"obs_domain":   func(r *Row) { r.ObsDomain = 2 },
		"protocol":     func(r *Row) { r.Protocol = "ipfix" },
		"ts":           func(r *Row) { r.TS = ts.Add(time.Second) },
		"start_ts":     func(r *Row) { r.StartTS = r.StartTS.Add(time.Second) },
		"src_addr":     func(r *Row) { r.SrcAddr = "10.1.1.9" },
		"dst_addr":     func(r *Row) { r.DstAddr = "10.2.2.9" },
		"src_port":     func(r *Row) { r.SrcPort = 1235 },
		"dst_port":     func(r *Row) { r.DstPort = 444 },
		"transport":    func(r *Row) { r.Transport = "udp" },
		"net_type":     func(r *Row) { r.NetType = "ipv6" },
		"in_if":        func(r *Row) { r.InIf = 3 },
		"out_if":       func(r *Row) { r.OutIf = 6 },
		"vlan":         func(r *Row) { r.VLAN = 101 },
		"tos":          func(r *Row) { r.ToS = 47 },
		"tcp_flags":    func(r *Row) { r.TCPFlags = 0x18 },
		"next_hop":     func(r *Row) { r.NextHop = "10.0.0.253" },
		"bytes":        func(r *Row) { r.Bytes = 1600 },
		"packets":      func(r *Row) { r.Packets = 4 },
		"sampling":     func(r *Row) { r.Sampling = 128 },
		"bytes_scaled": func(r *Row) { r.BytesScaled = 192_000 },
		"packets_scaled": func(r *Row) {
			r.PacketsScaled = 384
		},
		"src_asn":     func(r *Row) { r.SrcASN = 64502 },
		"src_as_name": func(r *Row) { r.SrcASName = "SRC-ALT" },
		"src_country": func(r *Row) { r.SrcCountry = "CA" },
		"dst_asn":     func(r *Row) { r.DstASN = 64503 },
		"dst_as_name": func(r *Row) { r.DstASName = "DST-ALT" },
		"dst_country": func(r *Row) { r.DstCountry = "FR" },
	} {
		r := base
		mutate(&r)
		if flowRowID(r) == flowRowID(base) {
			t.Errorf("changing %s did not change the dedup id (real flows would be collapsed)", name)
		}
	}
}

func TestMemoryFlowDedupKeepsRowsThatDifferOnlyByExtendedFields(t *testing.T) {
	ts := time.Unix(1_700_000_000, 0).UTC()
	base := Row{
		TenantID: "t-a", AgentID: "agent-1", Exporter: "10.0.0.1", ObsDomain: 1,
		Protocol: "netflow5", TS: ts, StartTS: ts.Add(-30 * time.Second),
		SrcAddr: "10.1.1.1", DstAddr: "10.2.2.2", SrcPort: 1234, DstPort: 443,
		Transport: "tcp", NetType: "ipv4", InIf: 2, OutIf: 5,
		Bytes: 1500, Packets: 3, Sampling: 64, BytesScaled: 96_000, PacketsScaled: 192,
	}
	vlanVariant := base
	vlanVariant.VLAN = 200
	flagsVariant := base
	flagsVariant.TCPFlags = 0x18
	samplingVariant := base
	samplingVariant.Sampling = 128
	samplingVariant.BytesScaled = 192_000
	samplingVariant.PacketsScaled = 384

	m := NewMemory()
	if err := m.Insert(context.TODO(), []Row{base, base, vlanVariant, flagsVariant, samplingVariant}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if got := m.Len(); got != 4 {
		t.Fatalf("memory dedup retained %d rows, want exact redelivery collapsed and three real variants preserved", got)
	}
}
