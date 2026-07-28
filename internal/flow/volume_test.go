// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package flow

import (
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/testsupport"
)

func meetsHighVolumeDecodeFloor(recordsPerSecond float64) bool {
	return recordsPerSecond >= 50_000
}

func TestHighVolumeDecodeFloor(t *testing.T) {
	if meetsHighVolumeDecodeFloor(49_999) {
		t.Fatal("planted decode regression crossed the 50k floor")
	}
	if !meetsHighVolumeDecodeFloor(50_000) {
		t.Fatal("the documented 50k boundary must pass")
	}
}

// TestHighVolumeDecode is the S38 high-volume ingest floor: decoding mixed
// v5/v9/sFlow traffic must sustain well above typical enterprise export rates.
// The floor (50k records/s) is deliberately conservative so slow CI runners
// pass; the benchmark below measures real headroom. A regression that tanks
// decode throughput (accidental allocation, quadratic template walk) trips it.
func TestHighVolumeDecode(t *testing.T) {
	d := NewDecoder(time.Hour, 1024)
	unix := uint32(testTime.Unix())

	// One v9 template, then a mixed packet set: 30-record v5, 10-record v9,
	// 1-record sFlow — approximating a busy edge.
	if _, _, err := d.Decode(buildNF9Template(1000, unix, 7, 260, nf9V4Fields), exporter, testTime); err != nil {
		t.Fatalf("template: %v", err)
	}
	v5recs := make([]nf5rec, 30)
	for i := range v5recs {
		v5recs[i] = nf5rec{src: [4]byte{10, 0, byte(i), 1}, dst: [4]byte{10, 0, byte(i), 2},
			pkts: 10, bytes: 1400, sport: uint16(1000 + i), dport: 443, proto: 6}
	}
	v5 := buildNF5(60_000, unix, 0x4004, v5recs)
	row := nf9V4Row([4]byte{172, 16, 0, 1}, [4]byte{172, 16, 0, 2}, 53, 33000, 17, 512, 4, 10_000, 20_000)
	v9 := buildNF9Data(100_000, unix, 7, 260, [][]byte{row, row, row, row, row, row, row, row, row, row})
	sf := buildSFlowRaw(1024, 5, 7, buildEthIPv4TCP(100, [4]byte{10, 1, 1, 1}, [4]byte{192, 0, 2, 9}, 443, 51000, 0x12, 6), false, false)

	const rounds = 2500 // 2500 x 41 = 102,500 records
	start := time.Now()
	var total int
	for i := 0; i < rounds; i++ {
		r1, _, _ := d.Decode(v5, exporter, testTime)
		r2, _, _ := d.Decode(v9, exporter, testTime)
		r3, _, _ := d.Decode(sf, exporter, testTime)
		total += len(r1) + len(r2) + len(r3)
	}
	elapsed := time.Since(start)

	if want := rounds * 41; total != want {
		t.Fatalf("decoded %d records, want %d", total, want)
	}
	perSec := float64(total) / elapsed.Seconds()
	t.Logf("high-volume decode: %d records in %v (%.0f records/s)", total, elapsed, perSec)
	if testsupport.RaceEnabled {
		t.Log("race instrumentation active: all mixed-flow records decoded correctly; the unchanged 50k wall floor is enforced by make test-performance without -race")
	} else if !meetsHighVolumeDecodeFloor(perSec) {
		t.Fatalf("decode throughput %.0f records/s below the 50k floor", perSec)
	}
}

// BenchmarkDecodeNetFlow5 measures the per-datagram hot path (30 records).
func BenchmarkDecodeNetFlow5(b *testing.B) {
	unix := uint32(testTime.Unix())
	recs := make([]nf5rec, 30)
	for i := range recs {
		recs[i] = nf5rec{src: [4]byte{10, 0, byte(i), 1}, dst: [4]byte{10, 0, byte(i), 2}, pkts: 1, bytes: 64, proto: 17}
	}
	pkt := buildNF5(1000, unix, 0, recs)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := decodeNetFlow5(pkt, exporter, testTime); err != nil {
			b.Fatal(err)
		}
	}
}
